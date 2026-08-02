# Core libraries
import streamlit as st
from PIL import Image
import numpy as np
import qrcode
import cv2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import io
import av
import threading
import random
from pathlib import Path
from streamlit_webrtc import webrtc_streamer, VideoProcessorBase

# Resolve base directory relative to this script (works on Streamlit Cloud)
BASE_DIR = Path(__file__).parent

# Ensuring pyzbar works
try:
    from pyzbar import pyzbar
except ImportError:
    st.error("ERROR: The 'pyzbar' library is not installed. Please install it (`pip install pyzbar`) and its system dependencies (e.g., `sudo apt-get install libzbar0` on Debian/Ubuntu) and restart the app.")
    st.stop()

# Configuration
AES_KEY_SIZE = 16 
IV_SIZE = 16
METADATA_LENGTH_BYTES = 4

# Helper Functions
def to_binary(data):
    if isinstance(data, str):
        return ''.join(format(ord(i), '08b') for i in data)
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return ''.join(format(i, '08b') for i in data)
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, '08b')
    else:
        raise TypeError("Type not supported for binary conversion")

def _extract_bits_from_image_generator(image: Image.Image):
    img_array = np.array(image)
    height, width, _ = img_array.shape
    for i in range(height):
        for j in range(width):
            for k in range(3):
                yield bin(img_array[i, j, k])[-1]

# Encryption / decryption Logic

def encrypt_message(message: str, key: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_CBC)
    message_bytes = message.encode('utf-8')
    padded_message = pad(message_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return cipher.iv, ciphertext

def decrypt_message(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_padded_message = cipher.decrypt(ciphertext)
    decrypted_message = unpad(decrypted_padded_message, AES.block_size)
    return decrypted_message.decode('utf-8')

# Steganography (LSB) logic for the main image

def encode_lsb(image: Image.Image, secret_data: bytes) -> Image.Image:
    width, height = image.size
    if image.mode != 'RGB':
        image = image.convert('RGB')

    max_bytes = (width * height * 3) // 8
    if len(secret_data) > max_bytes - METADATA_LENGTH_BYTES:
        raise ValueError(f"Message is too long. Max size: {max_bytes - METADATA_LENGTH_BYTES} bytes.")

    data_length_bytes = len(secret_data).to_bytes(METADATA_LENGTH_BYTES, 'big')
    data_to_hide = data_length_bytes + secret_data
    binary_data_to_hide = to_binary(data_to_hide)

    data_index = 0
    img_array = np.array(image).copy()

    for i in range(height):
        for j in range(width):
            for k in range(3):
                if data_index < len(binary_data_to_hide):
                    img_array[i, j, k] = (img_array[i, j, k] & 0xFE) | int(binary_data_to_hide[data_index])
                    data_index += 1
                else:
                    break
            if data_index >= len(binary_data_to_hide):
                break
        if data_index >= len(binary_data_to_hide):
            break

    return Image.fromarray(img_array)

def decode_lsb(image: Image.Image) -> bytes:
    if image.mode != 'RGB':
        image = image.convert('RGB')

    img_array = np.array(image)
    max_possible_bits = img_array.shape[0] * img_array.shape[1] * 3
    bit_generator = _extract_bits_from_image_generator(image)

    metadata_bits_to_extract = METADATA_LENGTH_BYTES * 8
    if max_possible_bits < metadata_bits_to_extract:
        raise ValueError("Image is too small to contain metadata.")

    try:
        binary_metadata = "".join(next(bit_generator) for _ in range(metadata_bits_to_extract))
    except StopIteration:
        raise ValueError("Could not extract full metadata.")

    secret_data_length = int(binary_metadata, 2)
    max_data_bytes = (max_possible_bits - metadata_bits_to_extract) // 8
    if not (0 < secret_data_length <= max_data_bytes):
        raise ValueError(f"Invalid data length in metadata: {secret_data_length} bytes.")

    data_bits_to_extract = secret_data_length * 8
    try:
        binary_data = "".join(next(bit_generator) for _ in range(data_bits_to_extract))
    except StopIteration:
        raise ValueError(f"Incomplete data. Expected {secret_data_length} bytes, but image ended.")

    if len(binary_data) < data_bits_to_extract:
        raise ValueError(f"Incomplete data. Expected {data_bits_to_extract} bits, got {len(binary_data)}.")

    return bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))


# QR code logic with decoy URL

def generate_decoy_qr(key: bytes, decoy_url: str) -> Image.Image:
    """Generates a QR code with a decoy URL. The key is appended as a URL fragment."""
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE:
        raise TypeError(f"Key must be a {AES_KEY_SIZE}-byte long bytes object.")
    if '#' in decoy_url:
        raise ValueError("Decoy URL cannot contain a '#' character.")

    full_url = f"{decoy_url}#{key.hex()}"

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(full_url)
    qr.make(fit=True)

    qr_image = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    return qr_image

def decode_key_from_qr(qr_image: Image.Image) -> bytes:
    if qr_image is None:
        raise ValueError("Input QR image cannot be None.")

    decoded_objects = pyzbar.decode(qr_image)
    if not decoded_objects:
        raise ValueError("No QR code found in the image.")

    full_url = decoded_objects[0].data.decode('utf-8')
    if '#' not in full_url:
        raise ValueError("QR code does not contain a key fragment ('#'). It might be an old or standard QR code.")

    parts = full_url.split('#')
    if len(parts) != 2 or not parts[1]:
        raise ValueError("QR code URL has an invalid format for key extraction.")

    key_hex = parts[1]
    try:
        key = bytes.fromhex(key_hex)
        if len(key) != AES_KEY_SIZE:
             raise ValueError(f"Decoded key has incorrect length. Expected {AES_KEY_SIZE}, got {len(key)}.")
        return key
    except (ValueError, TypeError):
        raise ValueError(f"The key fragment in the QR code is not a valid hex string.")


# Streamlit UI

st.set_page_config(layout="wide", page_title="Steganography Suite")
st.title("StegoQR: Hide Secrets in Plain Sight")
st.markdown("An application to hide encrypted text in images with a reliable QR code for the key.")

# Initialize session state
for key in ['stego_image_bytes', 'qr_image_bytes', 'scanned_qr_image', 'chosen_cover_image']:
    if key not in st.session_state:
        st.session_state[key] = None

tab1, tab2 = st.tabs(["Encode Message", "Decode Message"])

# ENCODE TAB
with tab1:
    st.header("1. Create Your Secret")
    st.info("A random 'cover' image will be chosen automatically when you generate the package.")
    
    st.subheader("Enter Your Secret Information")
    secret_text = st.text_area("Enter the text you want to hide:", height=150, key="secret_text")
    decoy_url = st.text_input(
        "Enter a decoy URL for the QR code:",
        "https://www.google.com/search?q=cute+cats",
        key="decoy_url"
    )
    st.info("This URL is what normal QR apps will see. The real key is hidden as a fragment in the QR data.")

    st.header("2. Generate Your Stego-Package")
    if st.button("Generate Stego Image & Key QR Code", type="primary"):
        if secret_text and decoy_url:
            try:
                # Randomly select a cover image (path resolved relative to script)
                image_number = random.randint(0, 9)
                cover_image_path = BASE_DIR / f"{image_number}.png"
                try:
                    cover_image = Image.open(cover_image_path)
                    # Store the chosen image to display it later
                    st.session_state.chosen_cover_image = cover_image
                except FileNotFoundError:
                    st.error(f"Error: Cover image '{cover_image_path}' not found. Make sure 0.png through 9.png are in the same directory as the script.")
                    st.stop()

                encryption_key = get_random_bytes(AES_KEY_SIZE)
                iv, ciphertext = encrypt_message(secret_text, encryption_key)
                data_to_hide = iv + ciphertext

                with st.spinner("Hiding encrypted data in the image..."):
                    stego_image = encode_lsb(cover_image, data_to_hide)

                with st.spinner("Generating your secure key QR code..."):
                    qr_code_image = generate_decoy_qr(encryption_key, decoy_url)

                buf_stego = io.BytesIO()
                stego_image.save(buf_stego, format="PNG")
                st.session_state.stego_image_bytes = buf_stego.getvalue()

                buf_qr = io.BytesIO()
                qr_code_image.save(buf_qr, format="PNG")
                st.session_state.qr_image_bytes = buf_qr.getvalue()

                st.success("Success! Your files are ready below.")

            except (ValueError, TypeError) as e:
                st.error(f"Error: {e}")
            except Exception as e:
                st.error(f"An unexpected error occurred: {e}")
        else:
            st.warning("Please provide secret text and a decoy URL.")

    if st.session_state.stego_image_bytes and st.session_state.qr_image_bytes:
        st.header("3. Download Your Files")
        res_col1, res_col2 = st.columns(2)
        with res_col1:
            if st.session_state.chosen_cover_image:
                st.subheader("Cover Image Used")
                st.image(st.session_state.chosen_cover_image, caption=f"Randomly selected: {st.session_state.chosen_cover_image.filename if hasattr(st.session_state.chosen_cover_image, 'filename') else 'Image'}")

            st.subheader("Stego Image (with hidden text)")
            st.image(st.session_state.stego_image_bytes)
            st.download_button("Download Stego Image", st.session_state.stego_image_bytes, "stego_image.png", "image/png")

        with res_col2:
            st.subheader("Key QR Code (with Decoy URL)")
            st.image(st.session_state.qr_image_bytes)
            st.download_button("Download QR Code", st.session_state.qr_image_bytes, "key_qr_code.png", "image/png")


# DECODE TAB
with tab2:
    st.header("1. Upload Your Stego-Package")
    dec_col1, dec_col2 = st.columns(2)

    with dec_col1:
        st.subheader("Upload Stego Image")
        stego_image_file = st.file_uploader("Choose the image with the hidden message...", type=['png'], key="decoder_stego")
        if stego_image_file:
            st.image(stego_image_file, caption="Your Stego Image")

    with dec_col2:
        st.subheader("Provide the Key QR Code")
        decode_method = st.radio("How will you provide the key?", ('Upload QR Code File', 'Scan QR Code with Camera'), key='decode_method')
        qr_code_file = None

        if decode_method == 'Upload QR Code File':
            st.session_state.scanned_qr_image = None
            qr_code_file = st.file_uploader("Choose the QR code PNG file...", type=['png'], key="decoder_qr_upload")
            if qr_code_file:
                st.image(qr_code_file, caption="Uploaded Key QR Code")
        else:
            # streamlit_webrtc already imported at top of file
            if st.session_state.get('scanned_qr_image'):
                st.success("QR Code Captured!")
                st.image(st.session_state.scanned_qr_image, caption="Captured QR Code")
                if st.button("Clear and Scan Again"):
                    st.session_state.scanned_qr_image = None
                    st.rerun()
            else:
                st.info("Hold your QR code up to the camera. A green box will appear when detected.")

                class VideoProcessor(VideoProcessorBase):
                    def __init__(self):
                        self.last_qr_region = None
                        self.lock = threading.Lock()

                    def recv(self, frame: av.VideoFrame) -> av.VideoFrame:
                        img = frame.to_ndarray(format="bgr24")
                        decoded_objects = pyzbar.decode(img)
                        if decoded_objects:
                            obj = decoded_objects[0]
                            (x, y, w, h) = obj.rect
                            # Crop the detected QR code region for capture
                            cropped_img = img[y:y+h, x:x+w]
                            with self.lock:
                                self.last_qr_region = cropped_img.copy()
                            # Draw rectangle on the displayed frame for user feedback
                            cv2.rectangle(img, (x, y), (x + w, y + h), (0, 255, 0), 2)
                            cv2.putText(img, "QR DETECTED", (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
                        
                        return av.VideoFrame.from_ndarray(img, format="bgr24")

                ctx = webrtc_streamer(key="qr_scanner", video_processor_factory=VideoProcessor, async_processing=True)

                if st.button("Capture Detected QR Code"):
                    if ctx.video_processor:
                        with ctx.video_processor.lock:
                            qr_region = ctx.video_processor.last_qr_region
                        if qr_region is not None:
                            st.session_state.scanned_qr_image = Image.fromarray(cv2.cvtColor(qr_region, cv2.COLOR_BGR2RGB))
                            st.rerun()
                        else:
                            st.warning("No QR code detected. Please hold it steady in the frame and try again.")

    st.header("2. Reveal the Secret")
    if st.button("Reveal Hidden Message", type="primary"):
        qr_image_to_decode = None
        if st.session_state.get('scanned_qr_image'):
            qr_image_to_decode = st.session_state.scanned_qr_image
        elif qr_code_file:
            qr_image_to_decode = Image.open(qr_code_file)

        if stego_image_file and qr_image_to_decode:
            try:
                stego_image = Image.open(stego_image_file)
                encryption_key = decode_key_from_qr(qr_image_to_decode)
                
                hidden_data = decode_lsb(stego_image)

                if len(hidden_data) < IV_SIZE:
                    raise ValueError(f"Hidden data is too short ({len(hidden_data)} bytes) to be valid.")

                iv = hidden_data[:IV_SIZE]
                ciphertext = hidden_data[IV_SIZE:]

                st.write("--- Decoding Details ---")
                st.code(f"Extracted Key:      {encryption_key.hex()}\n"
                        f"Decoy URL part:    {pyzbar.decode(qr_image_to_decode)[0].data.decode('utf-8').split('#')[0]}\n"
                        f"Extracted IV:        {iv.hex()}\n"
                        f"Extracted Ciphertext: {len(ciphertext)} bytes")

                if len(ciphertext) % AES.block_size != 0:
                    raise ValueError(f"Ciphertext length ({len(ciphertext)}) is not a multiple of block size ({AES.block_size}).")

                with st.spinner("Decrypting message..."):
                    decrypted_text = decrypt_message(iv, ciphertext, encryption_key)

                st.success("Secret Revealed!")
                st.text_area("Your hidden message is:", value=decrypted_text, height=200, disabled=True)

            except ValueError as e:
                if "padding" in str(e).lower() or "unpad" in str(e).lower():
                    st.error("Decryption Failed: Padding Error")
                    st.error("This almost always means the **Encryption Key is incorrect**.")
                    st.error("This can happen if you are using the wrong Stego-Image for this specific QR code.")
                else:
                    st.error(f"An error occurred: {e}")
            except Exception as e:
                st.error(f"An unexpected error occurred: {e}")
        else:
            st.warning("Please upload the stego image AND provide the QR code.")
