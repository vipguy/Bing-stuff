#!/usr/bin/env python3
# --- Script Details ---
# Script:     Pixel's DALL-E Image Generator GUI with Preview
# Author:     Primal Core
# Version:    2.0.3
# Description: Professional Tkinter GUI for generating AI images with interactive style variations, image preview, and scrollable image list.
# License:    MIT
# Dependencies: requests, rich, Pillow, tkinter
# Usage:      Run in Pydroid 3 to launch the GUI with image preview.

import os
import random
import re
import time
import logging
import glob
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from threading import Thread
from queue import Queue
import queue
from datetime import datetime
from urllib.parse import quote
from http.cookies import SimpleCookie
import requests
from PIL import Image, ImageTk
from io import BytesIO

try:
    from rich.logging import RichHandler
except ImportError:
    print("Error: 'rich' library is not installed. Please run 'pip install rich'.")
    exit(1)

# --- Configuration ---
LOG_FILE = "pixel_dalle_gen.log"
CONFIG_FILE = "pixel_dalle_config.ini"
BING_URL = "https://www.bing.com"
FORWARDED_IP = f"13.{random.randint(104, 107)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "cache-control": "no-cache",
    "content-type": "application/x-www-form-urlencoded",
    "referer": "https://www.bing.com/images/create/",
    "origin": "https://www.bing.com",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0"
    ),
    "x-forwarded-for": FORWARDED_IP,
    "sec-ch-ua": '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "upgrade-insecure-requests": "1",
}
DEFAULT_AUTH_COOKIE = "_U=YOUR_COOKIE_HERE"
SENSITIVE_WORDS = {"porn", "sex", "naked", "kill", "drug", "gore"}
ERROR_TIMEOUT = "Request timed out after 10 minutes."
ERROR_REDIRECT = "Failed to follow redirect. Please check cookie or network."
ERROR_BLOCKED_PROMPT = "Prompt blocked due to sensitive content."
ERROR_NO_IMAGES = "No images found in response."

# --- Popular Styles List ---
ALL_STYLES = [
    "watercolor", "oil painting", "impressionist", "renaissance", "baroque",
    "abstract", "surrealist", "cubist", "expressionist", "pop art",
    "cyberpunk", "synthwave", "vaporwave", "futuristic", "holographic",
    "anime", "cartoon", "chibi", "comic book", "pixel art",
    "ukiyo-e", "mandala", "art nouveau", "gothic", "folk art",
    "photorealistic", "minimalist", "steampunk", "low poly", "sketch"
]
STYLE_DESCRIPTIONS = {
    "watercolor": "Soft, translucent colors with fluid brushstrokes",
    "oil painting": "Rich, textured, vibrant traditional painting",
    "impressionist": "Loose brushwork, vibrant colors like Monet",
    "renaissance": "Classical, detailed, like Michelangelo",
    "baroque": "Dramatic, ornate, like Caravaggio",
    "abstract": "Non-representational shapes and colors",
    "surrealist": "Dreamlike, bizarre, like Dalí",
    "cubist": "Geometric, fragmented, like Picasso",
    "expressionist": "Emotional, bold, like Munch",
    "pop art": "Bold, colorful, like Warhol",
    "cyberpunk": "Neon, dystopian, high-tech urban",
    "synthwave": "Retro-futuristic, neon, 80s-inspired",
    "vaporwave": "Nostalgic, surreal, pastel digital",
    "futuristic": "Sleek, sci-fi, advanced tech",
    "holographic": "Iridescent, glowing, futuristic 3D",
    "anime": "Japanese animation, vibrant, expressive",
    "cartoon": "Simplified, exaggerated, Western animation",
    "chibi": "Cute, small, exaggerated anime characters",
    "comic book": "Bold outlines, superhero-inspired",
    "pixel art": "Retro, low-resolution digital art",
    "ukiyo-e": "Japanese woodblock print, elegant",
    "mandala": "Intricate, symmetrical, spiritual",
    "art nouveau": "Ornate, flowing, nature-inspired",
    "gothic": "Dark, medieval, architectural",
    "folk art": "Traditional, regional, handcrafted",
    "photorealistic": "Hyper-realistic, lifelike",
    "minimalist": "Simple, clean, minimal elements",
    "steampunk": "Victorian, mechanical, retro-futuristic",
    "low poly": "Geometric, polygonal 3D",
    "sketch": "Hand-drawn, pencil-like, rough"
}

# --- Exceptions ---
class PixelDalleGenError(Exception):
    pass

class BlockedPromptError(PixelDalleGenError):
    pass

class NetworkError(PixelDalleGenError):
    pass

# --- Utility Functions ---
def parse_cookie_string(cookie_string):
    cookie = SimpleCookie()
    cookie.load(cookie_string)
    return {key: morsel.value for key, morsel in cookie.items()}

def setup_logging(log_level="INFO"):
    log_level = getattr(logging, log_level.upper(), logging.INFO)
    logger = logging.getLogger("pixel_dalle_gen")
    logger.setLevel(log_level)
    logger.handlers = []
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(file_handler)
    return logger

def load_config():
    config = {"cookie": DEFAULT_AUTH_COOKIE, "output_dir": os.path.abspath("./PixelImages"), "custom_styles": ""}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                if "=" in line and not line.strip().startswith("#"):
                    key, value = [x.strip() for x in line.split("=", 1)]
                    config[key] = value
    custom_styles = config.get("custom_styles", "").split(",") if config["custom_styles"] else []
    custom_styles = [s.strip() for s in custom_styles if s.strip()]
    return config, custom_styles

def save_config(cookie, output_dir, custom_styles):
    with open(CONFIG_FILE, "w") as f:
        f.write(f"cookie={cookie}\n")
        f.write(f"output_dir={output_dir}\n")
        f.write(f"custom_styles={','.join(custom_styles)}\n")

def create_directory(output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    if not os.access(output_dir, os.W_OK):
        raise PermissionError(f"Output directory '{output_dir}' is not writable.")

def generate_filename(output_dir, index, style=None, file_format='png'):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    style_part = f"_{style.replace(' ', '_')}" if style else ""
    return os.path.join(output_dir, f"pixel_image{style_part}_{timestamp}_{index}.{file_format}")

def contains_sensitive_words(prompt):
    prompt_lower = prompt.lower()
    for word in SENSITIVE_WORDS:
        if word in prompt_lower:
            return True, word
    return False, None

def read_prompts_file(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Prompt file '{file_path}' not found.")
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def retry_request(func, max_attempts=3, base_delay=2):
    for attempt in range(max_attempts):
        try:
            return func()
        except NetworkError as e:
            if attempt == max_attempts - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))

# --- Core Image Generator Class ---
class PixelDalleGenerator:
    def __init__(self, auth_cookie, output_dir, logger, log_queue):
        self.auth_cookie = auth_cookie
        self.output_dir = os.path.abspath(output_dir)
        self.logger = logger
        self.log_queue = log_queue
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.cookies.update(parse_cookie_string(self.auth_cookie))
        create_directory(self.output_dir)

    def log(self, message, level="info"):
        getattr(self.logger, level.lower())(message)
        self.log_queue.put((level.upper(), message))

    def test_cookie(self):
        try:
            response = retry_request(lambda: self.session.get(f"{BING_URL}/images/create", timeout=30))
            if response.status_code == 200 and "create" in response.url:
                self.session.cookies.update(response.cookies)
                self.log("Cookie is valid!", "info")
                return True
            raise NetworkError(f"Invalid cookie or access denied: Status {response.status_code}")
        except NetworkError as e:
            raise NetworkError(f"Cookie test failed: {str(e)}")

    def _try_post_request(self, url, heatmap):
        def request():
            response = self.session.post(url, allow_redirects=False, data=heatmap, timeout=600)
            if "this prompt has been blocked" in response.text.lower():
                raise BlockedPromptError(ERROR_BLOCKED_PROMPT)
            return response if response.status_code == 302 else None
        return retry_request(request)

    def _fallback_get_images(self, url_encoded_prompt):
        def request():
            response = self.session.get(f"{BING_URL}/images/create?q={url_encoded_prompt}&FORM=GENCRE", timeout=600)
            self.log(f"GET response: Status {response.status_code}", "info")
            image_links = re.findall(r'src="([^"]+)"', response.text)
            normal_image_links = [
                link.split("?w=")[0] for link in image_links if "?w=" in link and link.startswith("https")
            ]
            normal_image_links = list(set(normal_image_links))
            if normal_image_links:
                self.log("Found images in HTML fallback", "info")
                return normal_image_links
            redirect_urls = re.findall(r'location\.href\s*=\s*"([^"]+)"', response.text)
            if redirect_urls:
                redirect_url = redirect_urls[0]
                request_id = redirect_url.split("id=")[-1] if "id=" in redirect_url else None
                if request_id:
                    self.session.get(f"{BING_URL}{redirect_url}")
                    polling_url = f"{BING_URL}/images/create/async/results/{request_id}?q={url_encoded_prompt}"
                    return self._poll_images(polling_url, images_per_style=4)
            form_actions = re.findall(r'<form[^>]+action="([^"]+)"', response.text)
            if form_actions:
                self.log("Trying form action endpoint", "info")
                url = f"{BING_URL}{form_actions[0]}"
                heatmap = f"q={url_encoded_prompt}&qs=ds"
                response = self.session.post(url, allow_redirects=False, data=heatmap, timeout=600)
                if response.status_code == 302:
                    redirect_url = response.headers["Location"].replace("&nfy=1", "")
                    request_id = redirect_url.split("id=")[-1]
                    self.session.get(f"{BING_URL}{redirect_url}")
                    polling_url = f"{BING_URL}/images/create/async/results/{request_id}?q={url_encoded_prompt}"
                    return self._poll_images(polling_url, images_per_style=4)
            raise NetworkError(ERROR_REDIRECT)
        return retry_request(request)

    def _poll_images(self, polling_url, images_per_style):
        start_time = time.time()
        while time.time() - start_time < 600:
            try:
                response = self.session.get(polling_url, timeout=30)
                if response.status_code == 200 and "errorMessage" not in response.text:
                    image_links = re.findall(r'src="([^"]+)"', response.text)
                    links = [link.split("?w=")[0] for link in image_links if "?w=" in link]
                    links = list(set(links))
                    if links:
                        num_images = min(len(links), images_per_style)
                        self.log(f"Using {num_images} image{'s' if num_images != 1 else ''} for this style", "info")
                        return links
                time.sleep(1)
            except requests.exceptions.RequestException:
                time.sleep(2)
        raise NetworkError(ERROR_TIMEOUT)

    def generate_images(self, prompt, styles=None, images_per_style=4, file_format='png'):
        if not prompt:
            raise ValueError("Prompt cannot be empty.")
        if images_per_style > 4:
            raise ValueError("Images per style cannot exceed 4.")
        blocked, word = contains_sensitive_words(prompt)
        if blocked:
            raise BlockedPromptError(f"Blocked due to: {word}")
        styles = styles or [None]
        all_saved_files = []
        for style in styles:
            styled_prompt = f"{prompt}, {style}" if style else prompt
            self.log(f"Generating {images_per_style} image{'s' if images_per_style != 1 else ''} for: {styled_prompt}", "info")
            try:
                self.test_cookie()
                url_encoded_prompt = quote(styled_prompt)
                heatmap = f"q={url_encoded_prompt}&qs=ds"
                preload_response = self.session.get(f"{BING_URL}/images/create", timeout=30)
                if preload_response.status_code == 200:
                    self.session.cookies.update(preload_response.cookies)
                    self.log("Preloaded page, captured cookies", "info")
                image_links = None
                for rt in ["4", "3", None]:
                    url = f"{BING_URL}/images/create?q={url_encoded_prompt}&FORM=GENCRE"
                    if rt:
                        url += f"&rt={rt}"
                    response = self._try_post_request(url, heatmap)
                    if response:
                        redirect_url = response.headers["Location"].replace("&nfy=1", "")
                        request_id = redirect_url.split("id=")[-1]
                        self.session.get(f"{BING_URL}{redirect_url}")
                        polling_url = f"{BING_URL}/images/create/async/results/{request_id}?q={url_encoded_prompt}"
                        image_links = self._poll_images(polling_url, images_per_style)
                        break
                if not image_links:
                    image_links = self._fallback_get_images(url_encoded_prompt)
                saved_files = self._save_images(image_links, images_per_style, style, file_format)
                all_saved_files.extend(saved_files)
                self.log(f"Saved {len(saved_files)} images for style '{style or 'none'}'", "info")
            except Exception as e:
                self.log(f"Error for '{styled_prompt}': {str(e)}", "error")
            time.sleep(2)
        return all_saved_files

    def _save_images(self, links, download_count, style=None, file_format='png'):
        num_to_download = min(download_count, len(links))
        self.log(f"Downloading {num_to_download} image{'s' if num_to_download != 1 else ''} to {self.output_dir} ({style or 'no style'})", "info")
        saved_files = []
        for i in range(num_to_download):
            try:
                link = links[i]
                response = self.session.get(link, timeout=30)
                if response.status_code == 200:
                    filename = generate_filename(self.output_dir, len(saved_files), style, file_format)
                    with open(filename, "wb") as f:
                        f.write(response.content)
                    saved_files.append(filename)
                else:
                    self.log(f"Failed to download image {i}: HTTP {response.status_code}", "error")
            except requests.exceptions.RequestException as e:
                self.log(f"Failed to download image {i}: {str(e)}", "error")
        if not saved_files:
            self.log(f"No images saved for style '{style or 'none'}'", "warning")
        return saved_files

    def create_thumbnail(self, image_path, thumbnail_path, size=(128, 128), output_format='png'):
        try:
            with Image.open(image_path) as img:
                img.thumbnail(size, Image.Resampling.LANCZOS)
                img.save(thumbnail_path, format=output_format.upper())
        except Image.UnidentifiedImageError:
            raise ValueError("Invalid or corrupted image file")
        except PermissionError:
            raise PermissionError(f"No write permission for {thumbnail_path}")

# --- Tkinter GUI with Image Preview ---
class PixelDalleGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pixel's DALL-E Image Generator v2.0.3")
        self.root.geometry("1200x800")  # Increased size to accommodate preview
        self.root.configure(bg="#2e2e2e")
        self.config, self.custom_styles = load_config()
        self.log_level = "INFO"
        self.logger = setup_logging(self.log_level)
        self.log_queue = Queue()
        self.output_dir = self.config["output_dir"]
        self.auth_cookie = self.config["cookie"]
        self.images_per_style = 4
        self.file_format = "png"
        self.selected_styles = []
        self.generator = PixelDalleGenerator(self.auth_cookie, self.output_dir, self.logger, self.log_queue)
        self.current_image = None  # For Tkinter PhotoImage
        self.setup_gui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.check_log_queue()

    def setup_gui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=6, relief="flat", background="#3a3a3a", foreground="white")
        style.map("TButton", background=[("active", "#4a4a4a")])
        style.configure("TLabel", background="#2e2e2e", foreground="white")
        style.configure("TEntry", fieldbackground="#3a3a3a", foreground="white")
        style.configure("TCombobox", fieldbackground="#3a3a3a", foreground="white")
        style.configure("Treeview", background="#3a3a3a", fieldbackground="#3a3a3a", foreground="white")
        style.configure("Treeview.Heading", background="#4a4a4a", foreground="white")

        # Main frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill="both", expand=True)

        # Left panel (controls)
        left_frame = ttk.Frame(main_frame, width=300)
        left_frame.pack(side="left", fill="y", padx=5)

        # Prompt input
        ttk.Label(left_frame, text="Prompt:").pack(anchor="w")
        self.prompt_entry = ttk.Entry(left_frame, width=40)
        self.prompt_entry.pack(fill="x", pady=5)
        ttk.Button(left_frame, text="Generate from Prompt", command=self.generate_from_prompt).pack(fill="x", pady=5)

        # Prompt file
        ttk.Label(left_frame, text="Prompt File:").pack(anchor="w")
        file_frame = ttk.Frame(left_frame)
        file_frame.pack(fill="x")
        self.file_entry = ttk.Entry(file_frame, width=30)
        self.file_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(file_frame, text="Browse", command=self.browse_prompt_file).pack(side="left")
        ttk.Button(left_frame, text="Generate from File", command=self.generate_from_file).pack(fill="x", pady=5)

        # Styles
        ttk.Label(left_frame, text="Styles:").pack(anchor="w")
        self.style_button = ttk.Button(left_frame, text="Select Styles (0)", command=self.open_style_selector)
        self.style_button.pack(fill="x", pady=5)

        # Settings
        ttk.Button(left_frame, text="Settings", command=self.open_settings).pack(fill="x", pady=5)

        # Image management
        ttk.Button(left_frame, text="Generate Thumbnails", command=self.generate_thumbnails).pack(fill="x", pady=5)
        ttk.Button(left_frame, text="List Images", command=self.list_images).pack(fill="x", pady=5)
        ttk.Button(left_frame, text="Clear Output Directory", command=self.clear_output_directory).pack(fill="x", pady=5)

        # Help
        ttk.Button(left_frame, text="Help", command=self.show_help).pack(fill="x", pady=5)

        # Right panel (logs, images, preview)
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=5)

        # Log area
        ttk.Label(right_frame, text="Logs:").pack(anchor="w")
        self.log_text = scrolledtext.ScrolledText(right_frame, height=10, bg="#3a3a3a", fg="white", insertbackground="white")
        self.log_text.pack(fill="both", pady=5)
        self.log_text.config(state="disabled")

        # Image list with scrollbar
        ttk.Label(right_frame, text="Generated Images:").pack(anchor="w")
        image_frame = ttk.Frame(right_frame)
        image_frame.pack(fill="both", pady=5)
        self.image_tree = ttk.Treeview(image_frame, columns=("Filename", "Style", "Creation Time"), show="headings", height=8)
        self.image_tree.heading("Filename", text="Filename")
        self.image_tree.heading("Style", text="Style")
        self.image_tree.heading("Creation Time", text="Creation Time")
        self.image_tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(image_frame, orient="vertical", command=self.image_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.image_tree.configure(yscrollcommand=scrollbar.set)
        self.image_tree.bind("<Double-1>", self.on_image_double_click)

        # Image preview
        ttk.Label(right_frame, text="Image Preview:").pack(anchor="w")
        self.preview_label = ttk.Label(right_frame, text="No image selected", background="#3a3a3a")
        self.preview_label.pack(fill="both", pady=5)

    def resize_image(self, image_path, max_size=(300, 300)):
        try:
            with Image.open(image_path) as img:
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                return ImageTk.PhotoImage(img)
        except Exception as e:
            self.log_message("ERROR", f"Failed to load image {image_path}: {str(e)}")
            return None

    def show_large_preview(self, image_path):
        try:
            with Image.open(image_path) as img:
                # Calculate size to fit within 80% of screen dimensions
                screen_width = self.root.winfo_screenwidth()
                screen_height = self.root.winfo_screenheight()
                max_width = int(screen_width * 0.8)
                max_height = int(screen_height * 0.8)
                img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)

                dialog = tk.Toplevel(self.root)
                dialog.title(os.path.basename(image_path))
                dialog.configure(bg="#2e2e2e")
                label = ttk.Label(dialog, image=photo)
                label.image = photo  # Keep reference
                label.pack(padx=10, pady=10)
                ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
        except Exception as e:
            self.log_message("ERROR", f"Failed to load large preview for {image_path}: {str(e)}")

    def update_preview(self, image_path):
        if not image_path or not os.path.exists(image_path):
            self.preview_label.config(image=None, text="No image selected")
            self.current_image = None
            return
        photo = self.resize_image(image_path)
        if photo:
            self.preview_label.config(image=photo, text="")
            self.current_image = photo  # Keep reference to avoid garbage collection
        else:
            self.preview_label.config(image=None, text="Failed to load image")

    def log_message(self, level, message):
        self.log_text.config(state="normal")
        color = {"INFO": "white", "WARNING": "yellow", "ERROR": "red"}.get(level, "white")
        self.log_text.insert("end", f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {level}] {message}\n", level)
        self.log_text.tag_config("INFO", foreground="white")
        self.log_text.tag_config("WARNING", foreground="yellow")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.config(state="disabled")
        self.log_text.see("end")

    def check_log_queue(self):
        try:
            while True:
                level, message = self.log_queue.get_nowait()
                self.log_message(level, message)
        except queue.Empty:
            pass
        self.root.after(100, self.check_log_queue)

    def browse_prompt_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, file_path)

    def open_style_selector(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Select Styles")
        dialog.geometry("600x500")
        dialog.configure(bg="#2e2e2e")

        ttk.Label(dialog, text=f"Select Styles ({self.images_per_style} images per style):").pack(pady=5)
        style_frame = ttk.Frame(dialog)
        style_frame.pack(fill="both", expand=True, padx=5, pady=5)
        canvas = tk.Canvas(style_frame, bg="#2e2e2e")
        scrollbar = ttk.Scrollbar(style_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        style_vars = {}
        for style in ALL_STYLES:
            var = tk.BooleanVar(value=style in self.selected_styles)
            style_vars[style] = var
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill="x", pady=2)
            ttk.Checkbutton(frame, text=f"{style} - {STYLE_DESCRIPTIONS.get(style, 'Custom style')}", variable=var).pack(anchor="w")

        def select_all():
            for var in style_vars.values():
                var.set(True)

        def clear_all():
            for var in style_vars.values():
                var.set(False)

        def confirm():
            self.selected_styles = [style for style, var in style_vars.items() if var.get()]
            self.style_button.config(text=f"Select Styles ({len(self.selected_styles)})")
            dialog.destroy()

        ttk.Button(dialog, text="Select All", command=select_all).pack(side="left", padx=5, pady=5)
        ttk.Button(dialog, text="Clear All", command=clear_all).pack(side="left", padx=5, pady=5)
        ttk.Button(dialog, text="Confirm", command=confirm).pack(side="right", padx=5, pady=5)

    def open_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Settings")
        dialog.geometry("500x400")
        dialog.configure(bg="#2e2e2e")

        ttk.Label(dialog, text="Output Directory:").pack(anchor="w", padx=5)
        output_frame = ttk.Frame(dialog)
        output_frame.pack(fill="x", padx=5, pady=5)
        output_entry = ttk.Entry(output_frame, width=40)
        output_entry.insert(0, self.output_dir)
        output_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(output_frame, text="Browse", command=lambda: output_entry.delete(0, "end") or output_entry.insert(0, filedialog.askdirectory())).pack(side="left")

        ttk.Label(dialog, text="Images per Style (1-4):").pack(anchor="w", padx=5)
        count_var = tk.StringVar(value=str(self.images_per_style))
        ttk.Spinbox(dialog, from_=1, to=4, textvariable=count_var, width=10).pack(anchor="w", padx=5, pady=5)

        ttk.Label(dialog, text="Log Level:").pack(anchor="w", padx=5)
        log_level_var = tk.StringVar(value=self.log_level)
        ttk.Combobox(dialog, textvariable=log_level_var, values=["DEBUG", "INFO", "WARNING", "ERROR"], state="readonly").pack(anchor="w", padx=5, pady=5)

        ttk.Label(dialog, text="Authentication Cookie:").pack(anchor="w", padx=5)
        cookie_entry = ttk.Entry(dialog, width=40)
        cookie_entry.insert(0, self.auth_cookie)
        cookie_entry.pack(fill="x", padx=5, pady=5)

        ttk.Label(dialog, text="Custom Styles (comma-separated):").pack(anchor="w", padx=5)
        custom_styles_entry = ttk.Entry(dialog, width=40)
        custom_styles_entry.insert(0, self.config["custom_styles"])
        custom_styles_entry.pack(fill="x", padx=5, pady=5)

        def save():
            self.output_dir = output_entry.get()
            self.images_per_style = int(count_var.get())
            self.log_level = log_level_var.get()
            self.auth_cookie = cookie_entry.get()
            self.config["output_dir"] = self.output_dir
            self.config["cookie"] = self.auth_cookie
            self.config["custom_styles"] = custom_styles_entry.get()
            self.custom_styles = [s.strip() for s in self.config["custom_styles"].split(",") if s.strip()]
            ALL_STYLES.extend([s for s in self.custom_styles if s not in ALL_STYLES])
            self.logger = setup_logging(self.log_level)
            self.generator = PixelDalleGenerator(self.auth_cookie, self.output_dir, self.logger, self.log_queue)
            save_config(self.auth_cookie, self.output_dir, self.custom_styles)
            dialog.destroy()

        ttk.Button(dialog, text="Save", command=save).pack(pady=10)

    def generate_from_prompt(self):
        prompt = self.prompt_entry.get().strip()
        if not prompt:
            messagebox.showerror("Error", "Prompt cannot be empty.")
            return
        total_images = len(self.selected_styles or [None]) * self.images_per_style
        if total_images > 12 and not messagebox.askyesno("Confirm", f"Generate {total_images} images for this prompt?"):
            return
        Thread(target=self.run_generate, args=(prompt,)).start()

    def generate_from_file(self):
        file_path = self.file_entry.get().strip()
        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "Prompt file not found.")
            return
        try:
            prompts = read_prompts_file(file_path)
            total_images = len(self.selected_styles or [None]) * self.images_per_style * len(prompts)
            if total_images > 12 and not messagebox.askyesno("Confirm", f"Generate {total_images} images for {len(prompts)} prompts?"):
                return
            Thread(target=self.run_generate_file, args=(prompts,)).start()
        except Exception as e:
            self.log_message("ERROR", f"Error reading prompt file: {str(e)}")

    def run_generate(self, prompt):
        try:
            saved_files = self.generator.generate_images(
                prompt, styles=self.selected_styles, images_per_style=self.images_per_style, file_format=self.file_format
            )
            self.log_message("INFO", f"Saved {len(saved_files)} images for '{prompt}'")
            with open(os.path.join(self.output_dir, "generation_log.txt"), "a") as log:
                log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Success: {prompt} - {len(saved_files)} images\n")
            self.list_images()
            if saved_files:
                self.update_preview(saved_files[-1])  # Preview the last generated image
        except Exception as e:
            self.log_message("ERROR", f"Error for '{prompt}': {str(e)}")
            with open(os.path.join(self.output_dir, "generation_log.txt"), "a") as log:
                log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Error: {prompt} - {str(e)}\n")

    def run_generate_file(self, prompts):
        for i, prompt in enumerate(prompts, 1):
            self.log_message("INFO", f"Processing prompt {i}/{len(prompts)}: {prompt}")
            try:
                saved_files = self.generator.generate_images(
                    prompt, styles=self.selected_styles, images_per_style=self.images_per_style, file_format=self.file_format
                )
                self.log_message("INFO", f"Saved {len(saved_files)} images for '{prompt}'")
                with open(os.path.join(self.output_dir, "generation_log.txt"), "a") as log:
                    log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Success: {prompt} - {len(saved_files)} images\n")
                self.list_images()
                if saved_files:
                    self.update_preview(saved_files[-1])  # Preview the last generated image
            except Exception as e:
                self.log_message("ERROR", f"Error for '{prompt}': {str(e)}")
                with open(os.path.join(self.output_dir, "generation_log.txt"), "a") as log:
                    log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Error: {prompt} - {str(e)}\n")
            time.sleep(2)

    def generate_thumbnails(self):
        image_extensions = ["*.png", "*.jpg", "*.jpeg"]
        image_files = []
        for ext in image_extensions:
            image_files.extend(glob.glob(os.path.join(self.output_dir, ext)))
        if not image_files:
            messagebox.showwarning("Warning", "No images found in output directory.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Thumbnails")
        dialog.geometry("600x500")
        dialog.configure(bg="#2e2e2e")

        ttk.Label(dialog, text="Select Images for Thumbnails:").pack(pady=5)
        listbox = tk.Listbox(dialog, selectmode="multiple", height=15, bg="#3a3a3a", fg="white")
        for i, image_path in enumerate(image_files, 1):
            listbox.insert("end", os.path.basename(image_path))
        listbox.pack(fill="both", padx=5, pady=5)

        ttk.Label(dialog, text="Thumbnail Size (pixels):").pack(anchor="w", padx=5)
        size_var = tk.StringVar(value="128")
        ttk.Entry(dialog, textvariable=size_var, width=10).pack(anchor="w", padx=5, pady=5)

        ttk.Label(dialog, text="Thumbnail Format:").pack(anchor="w", padx=5)
        format_var = tk.StringVar(value="png")
        ttk.Combobox(dialog, textvariable=format_var, values=["png", "jpg"], state="readonly").pack(anchor="w", padx=5, pady=5)

        overwrite_var = tk.BooleanVar()
        ttk.Checkbutton(dialog, text="Overwrite existing thumbnails", variable=overwrite_var).pack(anchor="w", padx=5, pady=5)

        def generate():
            selected_indices = listbox.curselection()
            if not selected_indices:
                messagebox.showwarning("Warning", "No images selected.")
                return
            selected_files = [image_files[i] for i in selected_indices]
            thumb_size = int(size_var.get())
            thumb_format = format_var.get()
            thumb_dir = os.path.join(self.output_dir, "thumbnails")
            create_directory(thumb_dir)

            if not messagebox.askyesno("Confirm", f"Generate {len(selected_files)} thumbnails (size: {thumb_size}x{thumb_size}, format: {thumb_format}) in {thumb_dir}?"):
                return

            generated = 0
            skipped = 0
            failed = 0
            for image_path in selected_files:
                thumb_filename = f"{os.path.splitext(os.path.basename(image_path))[0]}_thumb.{thumb_format}"
                thumb_path = os.path.join(thumb_dir, thumb_filename)
                if os.path.exists(thumb_path) and not overwrite_var.get():
                    self.log_message("WARNING", f"Skipped existing thumbnail: {thumb_filename}")
                    skipped += 1
                    continue
                try:
                    self.generator.create_thumbnail(image_path, thumb_path, size=(thumb_size, thumb_size), output_format=thumb_format)
                    self.log_message("INFO", f"Generated: {thumb_filename}")
                    generated += 1
                except Exception as e:
                    self.log_message("ERROR", f"Failed to generate thumbnail for {os.path.basename(image_path)}: {str(e)}")
                    failed += 1
            self.log_message("INFO", f"Thumbnail Generation Summary: {generated} generated, {skipped} skipped, {failed} failed")
            dialog.destroy()

        ttk.Button(dialog, text="Generate", command=generate).pack(pady=10)

    def list_images(self):
        for item in self.image_tree.get_children():
            self.image_tree.delete(item)
        image_extensions = ["*.png", "*.jpg", "*.jpeg"]
        image_files = []
        for ext in image_extensions:
            image_files.extend(glob.glob(os.path.join(self.output_dir, ext)))
        if not image_files:
            self.log_message("WARNING", "No images found in output directory.")
            self.update_preview(None)
            return
        for image_path in image_files:
            filename = os.path.basename(image_path)
            style_match = re.search(r'pixel_image_([^_]+)_[\d_]+\.\w+', filename)
            style = style_match.group(1).replace('_', ' ') if style_match else "None"
            creation_time = time.ctime(os.path.getctime(image_path))
            self.image_tree.insert("", "end", values=(filename, style, creation_time))
        self.log_message("INFO", "Listed generated images")
        # Preview the most recent image
        if image_files:
            self.update_preview(max(image_files, key=os.path.getctime))

    def on_image_double_click(self, event):
        selected = self.image_tree.selection()
        if selected:
            item = selected[0]
            filename = self.image_tree.item(item)["values"][0]
            image_path = os.path.join(self.output_dir, filename)
            self.update_preview(image_path)
            self.show_large_preview(image_path)

    def clear_output_directory(self):
        image_extensions = ["*.png", "*.jpg", "*.jpeg"]
        image_files = []
        for ext in image_extensions:
            image_files.extend(glob.glob(os.path.join(self.output_dir, ext)))
        if not image_files:
            self.log_message("WARNING", "No images found in output directory.")
            return
        if not messagebox.askyesno("Confirm", f"Delete {len(image_files)} images in {self.output_dir}?"):
            return
        for image_path in image_files:
            try:
                os.remove(image_path)
                self.log_message("INFO", f"Deleted: {os.path.basename(image_path)}")
            except Exception as e:
                self.log_message("ERROR", f"Error deleting {os.path.basename(image_path)}: {str(e)}")
        self.list_images()

    def show_help(self):
        help_text = (
            "Pixel's DALL-E Image Generator GUI - Help\n\n"
            "Overview:\n"
            "This GUI generates AI images using Bing's DALL-E integration, with a scrollable image list and preview panel.\n\n"
            "Features:\n"
            "- Generate images with a single prompt or from a file.\n"
            "- Select from 30+ styles (e.g., watercolor, cyberpunk, anime).\n"
            "- Scrollable image list for easy navigation.\n"
            "- Preview generated or selected images in the GUI.\n"
            "- Double-click an image in the list to view a larger preview in a pop-out window.\n"
            "- Manage settings (output directory, images per style, log level, cookie, custom styles).\n"
            "- Generate thumbnails for selected images.\n"
            "- List or clear generated images.\n\n"
            "Usage:\n"
            "- Enter a prompt or select a prompt file to generate images.\n"
            "- Use the 'Select Styles' button to choose styles.\n"
            "- Configure settings via the 'Settings' button.\n"
            "- Use 'Generate Thumbnails', 'List Images', or 'Clear Output Directory' for image management.\n"
            "- Double-click an image in the list to preview it in the GUI and open a larger preview window.\n"
            "- Logs are displayed in the right panel.\n\n"
            "Notes:\n"
            "- Images are saved in the output directory (default: ./PixelImages).\n"
            "- Prompt files should contain one prompt per line.\n"
            "- Custom styles can be added in the settings.\n"
            "- The preview panel shows the selected or most recently generated image, with a larger view available on double-click."
        )
        messagebox.showinfo("Help", help_text)

    def on_closing(self):
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            save_config(self.auth_cookie, self.output_dir, self.custom_styles)
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PixelDalleGUI(root)
    root.mainloop()
