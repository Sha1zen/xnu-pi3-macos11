#include "BCM2837PWMAudio.h"
#include "BCM2837PWMMath.h"

#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>

extern "C" {
void _disable_preemption(void);
void _enable_preemption(void);
}

#define super IOAudioDevice
OSDefineMetaClassAndStructors(BCM2837PWMAudioDevice, IOAudioDevice)

#undef super
#define super IOAudioEngine
OSDefineMetaClassAndStructors(BCM2837PWMAudioEngine, IOAudioEngine)

enum {
	kRegSourceAd = 0x0c,
	kDefaultRate = 48000,
	kDefaultRng  = kPWMTargetRange,
	kBytesPerRingFrame = kPWMAudioChannels * sizeof(uint32_t),
	kBytesPerSampleFrame = kPWMAudioChannels * sizeof(int16_t),
	kVolumeMax   = 100,
};

#undef super
#define super IOAudioDevice

bool
BCM2837PWMAudioDevice::initHardware(IOService *provider)
{
	if (!super::initHardware(provider)) {
		return false;
	}
	setDeviceName("Raspberry Pi 3.5mm Output");
	setDeviceShortName("Headphones");
	setManufacturerName("Raspberry Pi");
	setDeviceCanBeDefault(kIOAudioDeviceCanBeDefaultOutput | kIOAudioDeviceCanBeSystemOutput);

	BCM2837PWMAudioEngine *engine = new BCM2837PWMAudioEngine;
	if (engine == NULL) {
		return false;
	}
	bool ok = engine->init(NULL) && activateAudioEngine(engine) == kIOReturnSuccess;
	engine->release();
	return ok;
}

#undef super
#define super IOAudioEngine

bool
BCM2837PWMAudioEngine::initHardware(IOService *provider)
{
	if (!super::initHardware(provider)) {
		return false;
	}
	fPWM = NULL;
	fDMA = NULL;
	fSim = false;
	fHaveChannel = false;
	fRate = kDefaultRate;
	fRng = kDefaultRng;
	fSampleBuffer = NULL;
	fRingMem = NULL;
	fRing = NULL;
	fCbMem = NULL;
	fCb = NULL;
	fSimTimer = NULL;
	fVolume = kVolumeMax;
	fMute = false;
	fGainQ16 = 0x10000;

	// provider is the audio device; its provider is the PWM block.
	IOService *dev = provider;
	fPWM = OSDynamicCast(BCM2837PWM, dev ? dev->getProvider() : NULL);
	if (fPWM == NULL) {
		IOLog("BCM2837PWMAudio: provider is not BCM2837PWM\n");
		return false;
	}
	fPWM->retain();
	fSim = fPWM->isSimulated();

	if (!fSim) {
		IOService *d = IOService::waitForMatchingService(IOService::serviceMatching("BCM2837DMA"),
		    5ULL * 1000 * 1000 * 1000);
		fDMA = OSDynamicCast(BCM2837DMA, d);
		if (fDMA == NULL) {
			IOLog("BCM2837PWMAudio: no BCM2837DMA\n");
			OSSafeReleaseNULL(d);
			return false;
		}
		// waitForMatchingService returned it retained; keep that reference.
	}

	// Output ring: one 32-bit PWM word per channel per frame.
	void *ringV = NULL, *cbV = NULL;
	uint32_t cbBus = 0, ringBus = 0;
	fRingMem = BCM2837DMA::allocateBuffer(kPWMAudioFrames * kBytesPerRingFrame, 32, &ringV, &ringBus);
	fCbMem = BCM2837DMA::allocateBuffer(kPWMAudioPeriods * sizeof(BCM2837DMAControlBlock), 32, &cbV, &cbBus);
	if (fRingMem == NULL || fCbMem == NULL) {
		IOLog("BCM2837PWMAudio: DMA buffer allocation failed\n");
		return false;
	}
	fRing = (uint32_t *)ringV;
	fRingBus = ringBus;
	fCb = (BCM2837DMAControlBlock *)cbV;
	fCbBus = cbBus;
	fillRingMidScale(0, kPWMAudioFrames);

	fSampleBufferSize = kPWMAudioFrames * kBytesPerSampleFrame;
	fSampleBuffer = IOMalloc(fSampleBufferSize);
	if (fSampleBuffer == NULL) {
		return false;
	}
	bzero(fSampleBuffer, fSampleBufferSize);

	setDescription("Raspberry Pi 3.5mm Output");
	setNumSampleFramesPerBuffer(kPWMAudioFrames);
	IOAudioSampleRate r441 = { 44100, 0 }, r48 = { 48000, 0 };
	setSampleRate(&r48);

	IOAudioStream *stream = new IOAudioStream;
	if (stream == NULL || !stream->initWithAudioEngine(this, kIOAudioStreamDirectionOutput, 1, "Output")) {
		OSSafeReleaseNULL(stream);
		return false;
	}
	stream->setSampleBuffer(fSampleBuffer, fSampleBufferSize);
	IOAudioStreamFormat fmt;
	bzero(&fmt, sizeof(fmt));
	fmt.fNumChannels = kPWMAudioChannels;
	fmt.fSampleFormat = kIOAudioStreamSampleFormatLinearPCM;
	fmt.fNumericRepresentation = kIOAudioStreamNumericRepresentationSignedInt;
	fmt.fBitDepth = 16;
	fmt.fBitWidth = 16;
	fmt.fAlignment = kIOAudioStreamAlignmentHighByte;
	fmt.fByteOrder = kIOAudioStreamByteOrderLittleEndian;
	fmt.fIsMixable = 1;
	fmt.fDriverTag = 0;
	stream->addAvailableFormat(&fmt, &r441, &r441);
	stream->addAvailableFormat(&fmt, &r48, &r48);
	stream->setFormat(&fmt);
	IOReturn r = addAudioStream(stream);
	stream->release();
	if (r != kIOReturnSuccess) {
		return false;
	}

	IOAudioLevelControl *vol = IOAudioLevelControl::createVolumeControl(kVolumeMax, 0, kVolumeMax,
	    (IOFixed)(-40 * 65536), 0, kIOAudioControlChannelIDAll, kIOAudioControlChannelNameAll, 0,
	    kIOAudioControlUsageOutput);
	if (vol) {
		vol->setValueChangeHandler((IOAudioControl::IntValueChangeHandler)&BCM2837PWMAudioEngine::volumeChanged, this);
		addDefaultAudioControl(vol);
		vol->release();
	}
	IOAudioToggleControl *mute = IOAudioToggleControl::createMuteControl(false, kIOAudioControlChannelIDAll,
	    kIOAudioControlChannelNameAll, 0, kIOAudioControlUsageOutput);
	if (mute) {
		mute->setValueChangeHandler((IOAudioControl::IntValueChangeHandler)&BCM2837PWMAudioEngine::muteChanged, this);
		addDefaultAudioControl(mute);
		mute->release();
	}

	if (fSim) {
		IOWorkLoop *wl = getWorkLoop();
		fSimTimer = wl ? IOTimerEventSource::timerEventSource(this, &BCM2837PWMAudioEngine::simTimerFired) : NULL;
		if (fSimTimer == NULL || wl->addEventSource(fSimTimer) != kIOReturnSuccess) {
			return false;
		}
	}
	IOLog("BCM2837PWMAudio: engine ready (%s), %u frames, %u periods\n", fSim ? "simulated" : "PWM+DMA",
	    (unsigned)kPWMAudioFrames, (unsigned)kPWMAudioPeriods);
	return true;
}

void
BCM2837PWMAudioEngine::free()
{
	if (fSimTimer) {
		fSimTimer->cancelTimeout();
		IOWorkLoop *wl = getWorkLoop();
		if (wl) {
			wl->removeEventSource(fSimTimer);
		}
		fSimTimer->release();
		fSimTimer = NULL;
	}
	if (fHaveChannel && fDMA) {
		fDMA->freeChannel(fChannel);
		fHaveChannel = false;
	}
	if (fRingMem) {
		fRingMem->complete();
		fRingMem->release();
		fRingMem = NULL;
	}
	if (fCbMem) {
		fCbMem->complete();
		fCbMem->release();
		fCbMem = NULL;
	}
	if (fSampleBuffer) {
		IOFree(fSampleBuffer, fSampleBufferSize);
		fSampleBuffer = NULL;
	}
	OSSafeReleaseNULL(fDMA);
	OSSafeReleaseNULL(fPWM);
	super::free();
}

void
BCM2837PWMAudioEngine::fillRingMidScale(uint32_t firstFrame, uint32_t numFrames)
{
	if (fRing == NULL || firstFrame >= kPWMAudioFrames) {
		return;
	}
	if (firstFrame + numFrames > kPWMAudioFrames) {
		numFrames = kPWMAudioFrames - firstFrame;
	}
	uint32_t mid = fRng / 2;
	for (uint32_t i = 0; i < numFrames * kPWMAudioChannels; i++) {
		fRing[firstFrame * kPWMAudioChannels + i] = mid;
	}
}

void
BCM2837PWMAudioEngine::updateGain()
{
	uint32_t v = (uint32_t)fVolume;
	// Quadratic taper, 0..100 -> 0..1.0 in Q16.
	uint32_t g = fMute ? 0 : (uint32_t)(((uint64_t)v * v * 65536) / (kVolumeMax * kVolumeMax));
	fGainQ16 = g;
}

IOReturn
BCM2837PWMAudioEngine::volumeChanged(OSObject *target, IOAudioControl *, SInt32, SInt32 newValue)
{
	BCM2837PWMAudioEngine *me = OSDynamicCast(BCM2837PWMAudioEngine, target);
	if (me == NULL || newValue < 0 || newValue > kVolumeMax) {
		return kIOReturnBadArgument;
	}
	me->fVolume = newValue;
	me->updateGain();
	return kIOReturnSuccess;
}

IOReturn
BCM2837PWMAudioEngine::muteChanged(OSObject *target, IOAudioControl *, SInt32, SInt32 newValue)
{
	BCM2837PWMAudioEngine *me = OSDynamicCast(BCM2837PWMAudioEngine, target);
	if (me == NULL) {
		return kIOReturnBadArgument;
	}
	me->fMute = newValue != 0;
	me->updateGain();
	return kIOReturnSuccess;
}

IOReturn
BCM2837PWMAudioEngine::performFormatChange(IOAudioStream *, const IOAudioStreamFormat *,
    const IOAudioSampleRate *rate)
{
	if (rate) {
		if (rate->fraction != 0 || (rate->whole != 44100 && rate->whole != 48000)) {
			return kIOReturnUnsupported;
		}
		// Applied by performAudioEngineStart(); the family stops the engine
		// around a configuration change.
		fRate = rate->whole;
	}
	return kIOReturnSuccess;
}

void
BCM2837PWMAudioEngine::dmaCallback(void *ref, uint32_t, uint32_t cs)
{
	// Only the last control block raises an interrupt, so this is once per
	// trip round the ring: the time stamp IOAudioFamily wants at each wrap.
	if (cs & kDMACsInt) {
		((BCM2837PWMAudioEngine *)ref)->takeTimeStamp();
	}
}

void
BCM2837PWMAudioEngine::simTimerFired(OSObject *owner, IOTimerEventSource *sender)
{
	BCM2837PWMAudioEngine *me = OSDynamicCast(BCM2837PWMAudioEngine, owner);
	if (me == NULL || me->getState() != kIOAudioEngineRunning) {
		return;
	}
	me->takeTimeStamp();
	sender->setTimeoutUS((UInt32)((uint64_t)kPWMAudioFrames * 1000000 / me->fRate));
}

IOReturn
BCM2837PWMAudioEngine::performAudioEngineStart()
{
	uint32_t rng = 0, actual = 0;
	IOReturn r = fPWM->configure(fRate, &rng, &actual);
	if (r != kIOReturnSuccess) {
		IOLog("BCM2837PWMAudio: PWM configure(%u) failed %#x\n", fRate, r);
		return r;
	}
	fRng = rng;
	fillRingMidScale(0, kPWMAudioFrames);

	if (fSim) {
		clock_get_uptime(&fSimStartAbs);
		absolutetime_to_nanoseconds(fSimStartAbs, &fSimStartNs);
		takeTimeStamp(false);
		fSimTimer->setTimeoutUS((UInt32)((uint64_t)kPWMAudioFrames * 1000000 / fRate));
		fPWM->startOutput();
		return kIOReturnSuccess;
	}

	// One control block per period, looping; only the last interrupts.
	const uint32_t periodBytes = kPWMAudioFramesPerPeriod * kBytesPerRingFrame;
	for (uint32_t p = 0; p < kPWMAudioPeriods; p++) {
		BCM2837DMAControlBlock *cb = &fCb[p];
		bzero(cb, sizeof(*cb));
		cb->ti = kDMATiSrcInc | kDMATiDestDreq | kDMATiWaitResp | kDMATiPerMap(kBCM2837PWMDmaPerMap);
		if (p == kPWMAudioPeriods - 1) {
			cb->ti |= kDMATiIntEn;
		}
		cb->srcBus = fRingBus + p * periodBytes;
		cb->dstBus = (uint32_t)kBCM2837PWMFifoBus;
		cb->length = periodBytes;
		cb->nextBus = fCbBus + ((p + 1) % kPWMAudioPeriods) * (uint32_t)sizeof(BCM2837DMAControlBlock);
	}
	r = fDMA->allocateChannel(&fChannel, &BCM2837PWMAudioEngine::dmaCallback, this, true);
	if (r != kIOReturnSuccess) {
		return r;
	}
	fHaveChannel = true;
	// Order contract (BCM2837PWM.h): ring primed, DMA started, then PWM on.
	r = fDMA->startChannel(fChannel, fCbBus);
	if (r != kIOReturnSuccess) {
		fDMA->freeChannel(fChannel);
		fHaveChannel = false;
		return r;
	}
	takeTimeStamp(false);
	r = fPWM->startOutput();
	if (r != kIOReturnSuccess) {
		fDMA->freeChannel(fChannel);
		fHaveChannel = false;
	}
	return r;
}

IOReturn
BCM2837PWMAudioEngine::performAudioEngineStop()
{
	if (fSim) {
		fSimTimer->cancelTimeout();
	}
	if (fHaveChannel) {
		fDMA->freeChannel(fChannel);        // stops the DMA first
		fHaveChannel = false;
	}
	fPWM->stopOutput();
	return kIOReturnSuccess;
}

UInt32
BCM2837PWMAudioEngine::getCurrentSampleFrame()
{
	if (fSim) {
		uint64_t nowNs, startNs = fSimStartNs;
		AbsoluteTime now;
		clock_get_uptime(&now);
		absolutetime_to_nanoseconds(now, &nowNs);
		return (UInt32)(((nowNs - startNs) * fRate / 1000000000ULL) % kPWMAudioFrames);
	}
	if (!fHaveChannel) {
		return 0;
	}
	uint32_t src = fDMA->readChannelReg(fChannel, kRegSourceAd);
	if (src < fRingBus || src >= fRingBus + kPWMAudioFrames * kBytesPerRingFrame) {
		return 0;
	}
	return (src - fRingBus) / kBytesPerRingFrame;
}

IOReturn
BCM2837PWMAudioEngine::clipOutputSamples(const void *mixBuf, void *sampleBuf, UInt32 firstSampleFrame,
    UInt32 numSampleFrames, const IOAudioStreamFormat *streamFormat, IOAudioStream *)
{
	if (mixBuf == NULL || sampleBuf == NULL || streamFormat == NULL ||
	    streamFormat->fNumChannels != kPWMAudioChannels || streamFormat->fBitDepth != 16 ||
	    firstSampleFrame >= kPWMAudioFrames || numSampleFrames > kPWMAudioFrames - firstSampleFrame) {
		return kIOReturnBadArgument;
	}
	const float *mix = (const float *)mixBuf + firstSampleFrame * kPWMAudioChannels;
	int16_t *out = (int16_t *)sampleBuf + firstSampleFrame * kPWMAudioChannels;
	uint32_t *ring = fRing + firstSampleFrame * kPWMAudioChannels;
	const uint32_t n = numSampleFrames * kPWMAudioChannels;
	const int32_t gain = (int32_t)fGainQ16;
	const uint32_t rng = fRng;

	// Kernel FP registers are not preserved across a context switch.
	_disable_preemption();
	for (uint32_t i = 0; i < n; i++) {
		float f = mix[i];
		if (f > 1.0f) {
			f = 1.0f;
		} else if (f < -1.0f) {
			f = -1.0f;
		}
		int32_t s = (int32_t)(f * 32767.0f);
		s = (s * gain) >> 16;
		out[i] = (int16_t)s;
		ring[i] = pwmDatFromS16((int16_t)s, rng);
	}
	_enable_preemption();
	return kIOReturnSuccess;
}

IOReturn
BCM2837PWMAudioEngine::eraseOutputSamples(const void *, void *sampleBuf, UInt32 firstSampleFrame,
    UInt32 numSampleFrames, const IOAudioStreamFormat *, IOAudioStream *)
{
	if (sampleBuf == NULL || firstSampleFrame >= kPWMAudioFrames ||
	    numSampleFrames > kPWMAudioFrames - firstSampleFrame) {
		return kIOReturnBadArgument;
	}
	bzero((int16_t *)sampleBuf + firstSampleFrame * kPWMAudioChannels,
	    numSampleFrames * kBytesPerSampleFrame);
	fillRingMidScale(firstSampleFrame, numSampleFrames);
	return kIOReturnSuccess;
}
