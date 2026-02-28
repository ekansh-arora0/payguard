"""
Video Deepfake Detection
Extracts frames from video and runs DIRE face detection on each frame
"""

import json
import os
from typing import Dict, List, Optional

import cv2
import numpy as np
from PIL import Image


class VideoDeepfakeDetector:
    def __init__(self, dire_model=None):
        self.dire_model = dire_model
        self.frame_results = []
        self.face_detection_results = []

    def check_video(self, video_path: str, max_frames: int = 30) -> Dict:
        """
        Analyze a video for deepfake indicators.
        Extracts frames and runs face detection + DIRE on each.
        """
        self.frame_results = []
        self.face_detection_results = []

        if not os.path.exists(video_path):
            return {
                "error": "Video file not found",
                "is_deepfake": None,
                "confidence": 0,
            }

        try:
            cap = cv2.VideoCapture(video_path)

            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

            if total_frames == 0:
                return {
                    "error": "Could not read video",
                    "is_deepfake": None,
                    "confidence": 0,
                }

            frame_indices = np.linspace(
                0, total_frames - 1, min(max_frames, total_frames)
            )

            ai_face_count = 0
            real_face_count = 0
            no_face_count = 0

            for i, frame_idx in enumerate(frame_indices):
                cap.set(cv2.CAP_PROP_POS_FRAMES, int(frame_idx))
                ret, frame = cap.read()

                if not ret:
                    continue

                frame_result = {
                    "frame": int(frame_idx),
                    "ai_faces": 0,
                    "real_faces": 0,
                    "dire_score": None,
                }

                faces = self._detect_faces(frame)

                if len(faces) == 0:
                    no_face_count += 1
                else:
                    for face in faces:
                        if self.dire_model:
                            score = self._check_dire(face)
                            frame_result["dire_score"] = score
                            if score and score > 0.5:
                                ai_face_count += 1
                                self.face_detection_results.append(
                                    {
                                        "frame": int(frame_idx),
                                        "score": score,
                                        "is_ai": True,
                                    }
                                )
                            else:
                                real_face_count += 1
                                self.face_detection_results.append(
                                    {
                                        "frame": int(frame_idx),
                                        "score": score,
                                        "is_ai": False,
                                    }
                                )
                        else:
                            real_face_count += 1

                self.frame_results.append(frame_result)

            cap.release()

            total_faces = ai_face_count + real_face_count

            if total_faces == 0:
                confidence = 0
                is_deepfake = None
                message = "No faces detected in video"
            elif ai_face_count > 0:
                confidence = min(95, int((ai_face_count / total_faces) * 100) + 30)
                is_deepfake = True
                message = f"Detected {ai_face_count} AI-generated face(s) out of {total_faces} total faces"
            else:
                confidence = max(5, 50 - (no_face_count * 2))
                is_deepfake = False
                message = f"All {total_faces} detected faces appear real"

            return {
                "is_deepfake": is_deepfake,
                "confidence": confidence,
                "message": message,
                "total_frames_analyzed": len(self.frame_results),
                "total_faces": total_faces,
                "ai_faces": ai_face_count,
                "real_faces": real_face_count,
                "no_face_frames": no_face_count,
                "face_results": self.face_detection_results[:10],
            }

        except Exception as e:
            return {"error": str(e), "is_deepfake": None, "confidence": 0}

    def check_video_bytes(self, video_bytes: bytes, max_frames: int = 30) -> Dict:
        """Analyze video from bytes"""
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as f:
            f.write(video_bytes)
            temp_path = f.name

        try:
            result = self.check_video(temp_path, max_frames)
            return result
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def _detect_faces(self, frame) -> List:
        """Detect faces in a frame using OpenCV"""
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, 1.1, 4)

        face_images = []
        for x, y, w, h in faces:
            padding = int(w * 0.2)
            x1 = max(0, x - padding)
            y1 = max(0, y - padding)
            x2 = min(frame.shape[1], x + w + padding)
            y2 = min(frame.shape[0], y + h + padding)
            face_img = frame[y1:y2, x1:x2]
            face_images.append(face_img)

        return face_images

    def _check_dire(self, face_image) -> Optional[float]:
        """Check if face is AI-generated using DIRE"""
        if self.dire_model is None:
            return None

        try:
            face_rgb = cv2.cvtColor(face_image, cv2.COLOR_BGR2RGB)
            face_pil = Image.fromarray(face_rgb)

            result = self.dire_model.predict(face_pil)

            if hasattr(result, "item"):
                return result.item()
            return result

        except Exception:
            return None


def check_video_deepfake(video_path: str, dire_model=None) -> Dict:
    """Convenience function to check video for deepfakes"""
    detector = VideoDeepfakeDetector(dire_model)
    return detector.check_video(video_path)


def check_video_deepfake_bytes(video_bytes: bytes, dire_model=None) -> Dict:
    """Convenience function to check video from bytes"""
    detector = VideoDeepfakeDetector(dire_model)
    return detector.check_video_bytes(video_bytes)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        result = check_video_deepfake(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python video_deepfake_detector.py <video_path>")
