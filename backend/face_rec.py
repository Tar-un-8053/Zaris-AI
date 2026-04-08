# backend/face_rec.py
# Face recognition using OpenCV LBPH recognizer.

try:
    import cv2
except ImportError:
    cv2 = None

import json
import os
import time

import numpy as np


FACES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "faces_data")
MODEL_PATH = os.path.join(FACES_DIR, "face_model.yml")
NAMES_PATH = os.path.join(FACES_DIR, "names.json")

os.makedirs(FACES_DIR, exist_ok=True)

FACE_ENGINE_ERROR = None
face_cascade = None
recognizer = None
_model_loaded = False


def _initialize_face_engine():
    global FACE_ENGINE_ERROR, face_cascade, recognizer, _model_loaded

    FACE_ENGINE_ERROR = None
    face_cascade = None
    recognizer = None
    _model_loaded = False

    if cv2 is None:
        FACE_ENGINE_ERROR = "OpenCV install nahi hai. 'opencv-contrib-python' install karo."
        return

    if not hasattr(cv2, "face") or not hasattr(cv2.face, "LBPHFaceRecognizer_create"):
        FACE_ENGINE_ERROR = "OpenCV ka face module missing hai. 'opencv-contrib-python' install karo."
        return

    try:
        cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        face_cascade = cv2.CascadeClassifier(cascade_path)
        recognizer = cv2.face.LBPHFaceRecognizer_create()

        if os.path.exists(MODEL_PATH) and os.path.exists(NAMES_PATH):
            try:
                recognizer.read(MODEL_PATH)
                _model_loaded = True
                print("Face model loaded")
            except Exception:
                _model_loaded = False
    except Exception as exc:
        FACE_ENGINE_ERROR = f"Face engine init fail hua: {exc}"


def face_engine_ready():
    return FACE_ENGINE_ERROR is None and cv2 is not None and face_cascade is not None and recognizer is not None


def face_model_loaded():
    return _model_loaded and os.path.exists(MODEL_PATH)


def face_engine_message():
    return FACE_ENGINE_ERROR or "Face engine ready hai."


def get_face_status():
    """Returns (is_ready, status_message)"""
    if FACE_ENGINE_ERROR:
        return False, FACE_ENGINE_ERROR
    if not face_engine_ready():
        return False, "Face engine initialize nahi hua. 'opencv-contrib-python' install karo."
    if not _model_loaded:
        if os.path.exists(MODEL_PATH):
            return False, "Face model load karna padega. App restart karo."
        return False, "Face model trained nahi hai. Pehle 'security face enroll' ya UI se face register karo."
    return True, "Face recognition ready hai."


_initialize_face_engine()


def _load_names():
    if os.path.exists(NAMES_PATH):
        with open(NAMES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_names(names_dict):
    with open(NAMES_PATH, "w", encoding="utf-8") as f:
        json.dump(names_dict, f, ensure_ascii=False, indent=2)


def register_face(name, num_samples=30):
    if not face_engine_ready():
        return False, face_engine_message()

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return False, "Camera open nahi ho raha."

    names = _load_names()

    if name in names:
        face_id = names[name]
    else:
        face_id = max(names.values(), default=0) + 1
        names[name] = face_id

    person_dir = os.path.join(FACES_DIR, f"id_{face_id}")
    os.makedirs(person_dir, exist_ok=True)

    samples_taken = 0
    print(f"Face register shuru - {name} (ID: {face_id})")

    while samples_taken < num_samples:
        ret, frame = cap.read()
        if not ret:
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(
            gray, scaleFactor=1.2, minNeighbors=5, minSize=(100, 100)
        )

        for (x, y, w, h) in faces:
            samples_taken += 1
            face_img = gray[y : y + h, x : x + w]
            face_img = cv2.resize(face_img, (200, 200))

            img_path = os.path.join(person_dir, f"face_{samples_taken}.jpg")
            cv2.imwrite(img_path, face_img)

            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 255), 2)
            cv2.putText(
                frame,
                f"{name} - {samples_taken}/{num_samples}",
                (x, y - 10),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (0, 255, 255),
                2,
            )

        cv2.imshow("Owner Face Enrollment - Press Q to cancel", frame)

        key = cv2.waitKey(100) & 0xFF
        if key == ord("q"):
            break

    cap.release()
    cv2.destroyAllWindows()

    if samples_taken >= 10:
        _save_names(names)
        _train_model()
        return True, f"{name} ka face register ho gaya! ({samples_taken} samples)"

    return False, f"Sirf {samples_taken} samples mile. Thoda aur stable frame ke saath dobara try karo."


def _train_model():
    global _model_loaded, recognizer

    if not face_engine_ready():
        return False

    names = _load_names()
    if not names:
        return False

    faces = []
    labels = []

    for name, face_id in names.items():
        person_dir = os.path.join(FACES_DIR, f"id_{face_id}")
        if not os.path.exists(person_dir):
            continue

        for img_file in os.listdir(person_dir):
            if not img_file.endswith(".jpg"):
                continue

            img_path = os.path.join(person_dir, img_file)
            img = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)
            if img is None:
                continue

            img = cv2.resize(img, (200, 200))
            faces.append(img)
            labels.append(face_id)

    if len(faces) < 5:
        print("Not enough face data to train")
        return False

    print(f"Training face model - {len(faces)} samples, {len(names)} persons...")
    recognizer = cv2.face.LBPHFaceRecognizer_create()
    recognizer.train(faces, np.array(labels))
    recognizer.write(MODEL_PATH)
    _model_loaded = True

    print("Face model trained and saved")
    return True


def recognize_face(timeout=5, show_window=True):
    global _model_loaded

    if not face_engine_ready():
        return None, 0

    if not _model_loaded:
        if os.path.exists(MODEL_PATH):
            try:
                recognizer.read(MODEL_PATH)
                _model_loaded = True
            except Exception:
                return None, 0

    if not _model_loaded:
        return None, 0

    names = _load_names()
    if not names:
        return None, 0

    id_to_name = {value: key for key, value in names.items()}

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        return None, 0

    start_time = time.time()
    best_name = None
    best_confidence = 999

    while time.time() - start_time < timeout:
        ret, frame = cap.read()
        if not ret:
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(
            gray, scaleFactor=1.2, minNeighbors=5, minSize=(100, 100)
        )

        for (x, y, w, h) in faces:
            face_img = gray[y : y + h, x : x + w]
            face_img = cv2.resize(face_img, (200, 200))

            label, confidence = recognizer.predict(face_img)

            if confidence < best_confidence:
                best_confidence = confidence
                if label in id_to_name:
                    best_name = id_to_name[label]

            if show_window:
                if confidence < 80:
                    name_text = id_to_name.get(label, "Unknown")
                    color = (0, 255, 0)
                else:
                    name_text = "Unknown"
                    color = (0, 0, 255)

                cv2.rectangle(frame, (x, y), (x + w, y + h), color, 2)
                cv2.putText(
                    frame,
                    f"{name_text} ({confidence:.0f})",
                    (x, y - 10),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.7,
                    color,
                    2,
                )

        if show_window:
            cv2.imshow("Owner Face Verification", frame)
            key = cv2.waitKey(50) & 0xFF
            if key == ord("q"):
                break
        else:
            cv2.waitKey(1)

        if best_confidence < 60:
            if show_window:
                time.sleep(0.5)
            break

    cap.release()
    if show_window:
        cv2.destroyAllWindows()

    if best_name and best_confidence < 80:
        print(f"Face recognized: {best_name} (confidence: {best_confidence:.0f})")
        return best_name, best_confidence

    return None, best_confidence


def get_registered_faces():
    names = _load_names()
    return list(names.keys())


def delete_face(name):
    names = _load_names()
    if name not in names:
        return False, f"{name} ka face registered nahi hai!"

    face_id = names[name]
    person_dir = os.path.join(FACES_DIR, f"id_{face_id}")

    if os.path.exists(person_dir):
        import shutil

        shutil.rmtree(person_dir)

    del names[name]
    _save_names(names)

    if names and face_engine_ready():
        _train_model()
    elif not names and os.path.exists(MODEL_PATH):
        os.remove(MODEL_PATH)
        global _model_loaded
        _model_loaded = False

    return True, f"{name} ka face delete ho gaya!"
