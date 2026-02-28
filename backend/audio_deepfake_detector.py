"""
Audio Deepfake Detection
Analyzes audio for AI-generated voice patterns
Uses spectral analysis and voice feature extraction
"""

import os
import json
from typing import Dict, List, Tuple, Optional
import numpy as np


class AudioDeepfakeDetector:
    def __init__(self):
        self.findings = []
        self.confidence = 0.0
    
    def check_audio(self, audio_path: str) -> Dict:
        """Analyze audio file for AI voice indicators"""
        self.findings = []
        self.confidence = 0.0
        
        if not os.path.exists(audio_path):
            return {"error": "Audio file not found", "is_deepfake": None, "confidence": 0}
        
        try:
            import librosa
            import soundfile as sf
            
            y, sr = librosa.load(audio_path, sr=16000)
            
            self._check_spectral_features(y, sr)
            self._check_voice_quality(y, sr)
            self._check_artifacts(y, sr)
            
            is_deepfake = self.confidence > 50
            
            return {
                "is_deepfake": is_deepfake,
                "confidence": int(self.confidence),
                "findings": self.findings,
                "duration_sec": round(len(y) / sr, 2),
                "sample_rate": sr
            }
            
        except ImportError:
            return {"error": "librosa required for audio analysis", "is_deepfake": None, "confidence": 0}
        except Exception as e:
            return {"error": str(e), "is_deepfake": None, "confidence": 0}
    
    def check_audio_bytes(self, audio_bytes: bytes) -> Dict:
        """Analyze audio from bytes"""
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as f:
            f.write(audio_bytes)
            temp_path = f.name
        
        try:
            result = self.check_audio(temp_path)
            return result
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    def _add_finding(self, indicator: str, confidence: int, details: str = ""):
        """Add a finding"""
        self.findings.append({
            "indicator": indicator,
            "confidence": confidence,
            "details": details
        })
        self.confidence = max(self.confidence, confidence)
    
    def _check_spectral_features(self, y, sr):
        """Check spectral features for AI indicators"""
        import librosa
        
        S = np.abs(librosa.stft(y))
        spectral_centroid = librosa.feature.spectral_centroid(S=S, sr=sr)[0]
        spectral_rolloff = librosa.feature.spectral_rolloff(S=S, sr=sr)[0]
        
        centroid_mean = np.mean(spectral_centroid)
        rolloff_mean = np.mean(spectral_rolloff)
        
        if centroid_mean > 4000:
            self._add_finding("Spectral-Center", 25, f"High centroid: {centroid_mean:.0f}Hz")
        
        if rolloff_mean > 7000:
            self._add_finding("Spectral-Rolloff", 25, f"High rolloff: {rolloff_mean:.0f}Hz")
        
        spectral_bandwidth = librosa.feature.spectral_bandwidth(S=S, sr=sr)[0]
        if np.std(spectral_bandwidth) < 500:
            self._add_finding("Spectral-BW", 20, "Unusually uniform bandwidth (AI indicator)")
    
    def _check_voice_quality(self, y, sr):
        """Check voice quality metrics"""
        import librosa
        
        try:
            pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
            pitch_values = []
            for t in range(pitches.shape[1]):
                index = magnitudes[:, t].argmax()
                pitch = pitches[index, t]
                if pitch > 0:
                    pitch_values.append(pitch)
            
            if pitch_values:
                pitch_mean = np.mean(pitch_values)
                pitch_std = np.std(pitch_values)
                
                if pitch_std < 20:
                    self._add_finding("Pitch-Stable", 30, f"Unnaturally stable pitch (std: {pitch_std:.1f})")
                
                if 50 < pitch_mean < 300:
                    pass
                else:
                    self._add_finding("Pitch-Range", 20, f"Unusual pitch: {pitch_mean:.0f}Hz")
                    
        except:
            pass
    
    def _check_artifacts(self, y, sr):
        """Check for digital artifacts common in AI audio"""
        import librosa
        
        frame_length = 2048
        hop_length = 512
        
        zcr = librosa.feature.zero_crossing_rate(y, frame_length=frame_length, hop_length=hop_length)[0]
        
        if np.mean(zcr) < 0.05:
            self._add_finding("ZCR-Low", 25, f"Very low zero-crossing rate (AI audio often too clean)")
        
        rms = librosa.feature.rms(y=y, frame_length=frame_length, hop_length=hop_length)[0]
        
        if np.std(rms) < 0.02:
            self._add_finding("RMS-Stable", 20, "Unusually consistent amplitude (AI indicator)")
        
        if np.max(rms) / (np.mean(rms) + 1e-10) < 3:
            self._add_finding("RMS-Dynamic", 25, "Low dynamic range (AI audio characteristic)")


def check_audio_deepfake(audio_path: str) -> Dict:
    """Convenience function"""
    detector = AudioDeepfakeDetector()
    return detector.check_audio(audio_path)


def check_audio_deepfake_bytes(audio_bytes: bytes) -> Dict:
    """Convenience function from bytes"""
    detector = AudioDeepfakeDetector()
    return detector.check_audio_bytes(audio_bytes)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = check_audio_deepfake(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python audio_deepfake_detector.py <audio_file>")
