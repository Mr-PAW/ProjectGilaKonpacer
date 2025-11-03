# cobain import cv2 (adalah face recognition)
try:
    import cv2
    # face module is in opencv-contrib-python
    has_cv2_face = hasattr(cv2, 'face')
except Exception as e:
    cv2 = None
    has_cv2_face = False

if cv2:
    try:
        HAAR_CASCADE = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
    except Exception:
        HAAR_CASCADE = None
