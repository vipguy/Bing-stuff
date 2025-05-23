#!/usr/bin/env python3
# =====================================
# Script:     Bing Image Generator
# Author:     Primal Core + Updated by Assistant
# Version:    1.8.4 + theme toggle update
# Description: Fetches AI-generated images from Bing using a prompt and saves them to a directory.
# License:    MIT
# Dependencies: requests, rich, tkinter, pillow
# Notes:      Run this script in Pydroid 3's editor, not the terminal/REPL.
#             Tap/click image previews to enlarge them. Enlarged view optimized for mobile.
# =====================================

import os
import random
import re
import time
import logging
import threading
from http.cookies import SimpleCookie
import requests
from urllib.parse import quote
from rich.console import Console
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

# --- Configuration ---

console = Console()

BING_URL = os.getenv("BING_URL", "https://www.bing.com")

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

SENSITIVE_WORDS = {
    "porn", "pornographic", "xxx", "sex", "naked", "boobs", "breasts", "penis", "vagina",
    "racist", "nigger", "faggot", "bitch", "slut", "whore",
    "kill", "murder", "suicide", "abuse", "terrorist", "terrorism", "bomb", "shooting",
    "drug", "drugs", "cocaine", "heroin", "hack", "hacking", "piracy", "crime",
    "gore", "blood", "mutilation", "torture", "corpse", "decapitation",
    "phishing", "malware", "virus", "ransomware", "trojan",
}

ERROR_TIMEOUT = "Request timed out after 10 minutes."
ERROR_REDIRECT = "Failed to follow redirect. Bing may have changed its API."
ERROR_BLOCKED_PROMPT = "Prompt blocked by Bing. Try rephrasing or removing sensitive words."
ERROR_NORESULTS = "No results received from Bing."
ERROR_NO_IMAGES = "No images found in Bing's response."

# --- Custom Exceptions ---

class BingImageGenError(Exception):
    """Base exception for Bing Image Generator errors."""
    pass

class BlockedPromptError(BingImageGenError):
    """Raised when the prompt contains sensitive words or is blocked by Bing."""
    pass

class InvalidCookieError(BingImageGenError):
    """Raised when the authentication cookie is invalid or access is denied."""
    pass

class NetworkError(BingImageGenError):
    """Raised when a network-related error occurs."""
    pass

class NoImagesError(BingImageGenError):
    """Raised when no images are found in the response."""
    pass

class TimeoutError(BingImageGenError):
    """Raised when the request exceeds the timeout duration."""
    pass

# --- Utility Functions ---

def setup_logging(quiet=False):
    """Configure logging for the script."""
    logging.basicConfig(
        level=logging.WARNING if quiet else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger(__name__)

def parse_cookie_string(cookie_string):
    """Parse a cookie string into a dictionary."""
    cookie = SimpleCookie()
    cookie.load(cookie_string)
    return {key: morsel.value for key, morsel in cookie.items()}

def contains_sensitive_words(prompt, sensitive_words):
    """Check if the prompt contains sensitive words."""
    prompt_lower = prompt.lower()
    for word in sensitive_words:
        pattern = fr"\b{re.escape(word)}\b"
        if re.search(pattern, prompt_lower):
            return True, word
    return False, None

def url_encode_prompt(prompt):
    """URL-encode the prompt for safe use in requests."""
    return quote(prompt)

def create_directory(output_dir):
    """Create the output directory if it doesn't exist."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        console.print(f"[bold green]Created directory:[/bold green] {output_dir}")
    if not os.access(output_dir, os.W_OK):
        raise PermissionError(f"Output directory '{output_dir}' is not writable.")

def generate_filename(output_dir, index):
    """Generate a unique filename for an image."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(output_dir, f"bing_image_{timestamp}_{index}.png")

# --- Core Image Generator Class ---

class BingImageGenerator:
    """A class to generate and save images from Bing's AI image creator."""

    def __init__(self, auth_cookie=None, output_dir="BingImages", quiet=False, logger_callback=None):
        """Initialize the Bing Image Generator."""
        self.auth_cookie = auth_cookie or os.getenv("BING_AUTH_COOKIE") or DEFAULT_AUTH_COOKIE
        self.output_dir = os.path.abspath(output_dir)
        self.quiet = quiet
        self.logger = setup_logging(quiet)
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.logger_callback = logger_callback

        if not self.auth_cookie:
            raise InvalidCookieError("No authentication cookie provided.")
        self.session.cookies.update(parse_cookie_string(self.auth_cookie))
        create_directory(self.output_dir)

    def log(self, message, level="info"):
        """Log a message using the callback if available."""
        if self.logger_callback:
            self.logger_callback(message, level)
        if level == "info":
            console.print(message)
        elif level == "error":
            console.print(f"[bold red]{message}[/bold red]")
        elif level == "warning":
            console.print(f"[bold yellow]{message}[/bold yellow]")
        elif level == "success":
            console.print(f"[bold green]{message}[/bold green]")

    def test_cookie(self):
        """Test if the authentication cookie is valid."""
        self.log("Verifying authentication cookie...")
        try:
            response = self.session.get(f"{BING_URL}/images/create", timeout=30)
            if response.status_code == 200 and "create" in response.url and "form" in response.text.lower():
                self.session.cookies.update(response.cookies)
                self.log("✓ Cookie is valid!", "success")
                return True
            raise InvalidCookieError(f"Invalid cookie or access denied: Status {response.status_code}")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Cookie test failed: {str(e)}")

    def _try_post_request(self, url, payload):
        """Attempt a POST request and return response if successful."""
        try:
            response = self.session.post(url, allow_redirects=False, data=payload, timeout=600)
            if "this prompt has been blocked" in response.text.lower():
                raise BlockedPromptError(ERROR_BLOCKED_PROMPT)
            return response if response.status_code == 302 else None
        except requests.exceptions.RequestException as e:
            self.log(f"⚠️ POST request failed: {str(e)}", "warning")
            raise NetworkError(f"POST request failed: {str(e)}")

    def _fallback_get_images(self, url_encoded_prompt):
        """Fallback to GET request and parse HTML for images or redirects."""
        self.log("Falling back to GET request...")
        try:
            response = self.session.get(
                f"{BING_URL}/images/create?q={url_encoded_prompt}&FORM=GENCRE", timeout=600
            )
            self.log(f"GET response: Status {response.status_code}")

            image_links = re.findall(r'src="([^"]+)"', response.text)
            normal_image_links = [
                link.split("?w=")[0] for link in image_links if "?w=" in link and link.startswith("https")
            ]
            normal_image_links = list(set(normal_image_links))
            if normal_image_links:
                self.log("Found images in HTML fallback", "success")
                return normal_image_links

            redirect_urls = re.findall(r'location\.href\s*=\s*"([^"]+)"', response.text)
            if redirect_urls:
                redirect_url = redirect_urls[0]
                request_id = redirect_url.split("id=")[-1] if "id=" in redirect_url else None
                if request_id:
                    self.session.get(f"{BING_URL}{redirect_url}")
                    polling_url = f"{BING_URL}/images/create/async/results/{request_id}?q={url_encoded_prompt}"
                    return self._poll_images(polling_url)

            form_actions = re.findall(r'<form[^>]+action="([^"]+)"', response.text)
            if form_actions:
                self.log("Trying form action endpoint")
                url = f"{BING_URL}{form_actions[0]}"
                payload = f"q={url_encoded_prompt}&qs=ds"
                response = self.session.post(url, allow_redirects=False, data=payload, timeout=600)
                if response.status_code == 302:
                    redirect_url = response.headers["Location"].replace("&nfy=1", "")
                    request_id = redirect_url.split("id=")[-1]
                    self.session.get(f"{BING_URL}{redirect_url}")
                    polling_url = f"{BING_URL}/images/create/async/results/{request_id}?q={url_encoded_prompt}"
                    return self._poll_images(polling_url)

            raise NoImagesError(ERROR_REDIRECT)
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Fallback GET failed: {str(e)}")

    def _poll_images(self, polling_url):
        """Poll the async results URL for image links."""
        self.log("Waiting for Bing to generate images...")
        start_wait = time.time()
        total_duration = 600  # 10 minutes

        while True:
            elapsed = int(time.time() - start_wait)
            if elapsed > total_duration:
                raise TimeoutError(ERROR_TIMEOUT)
            self.log(f"Polling for images... {elapsed}s elapsed")
            try:
                response = self.session.get(polling_url, timeout=30)
                if response.status_code != 200:
                    raise NoImagesError(ERROR_NORESULTS)
                if response.text and "errorMessage" not in response.text:
                    break
                time.sleep(1)
            except requests.exceptions.RequestException as e:
                self.log(f"⚠️ Polling failed: {str(e)}", "warning")
                time.sleep(2)

        image_links = re.findall(r'src="([^"]+)"', response.text)
        normal_image_links = [link.split("?w=")[0] for link in image_links if "?w=" in link]
        normal_image_links = list(set(normal_image_links))
        if not normal_image_links:
            raise NoImagesError(ERROR_NO_IMAGES)
        self.log(f"Found {len(normal_image_links)} image links")
        self.log("✓ Images generated successfully!", "success")
        return normal_image_links

    def generate_images(self, prompt, download_count=4):
        """Generate and save images for the given prompt."""
        if not prompt:
            raise ValueError("Prompt cannot be empty.")
        if download_count > 4:
            raise ValueError("Download count cannot exceed 4.")

        blocked, blocked_word = contains_sensitive_words(prompt, SENSITIVE_WORDS)
        if blocked:
            raise BlockedPromptError(f"Prompt blocked due to sensitive word: '{blocked_word}'.")

        self.test_cookie()

        self.log(f"Generating images for prompt: {prompt}")
        try:
            url_encoded_prompt = url_encode_prompt(prompt)
            payload = f"q={url_encoded_prompt}&qs=ds"

            preload_response = self.session.get(f"{BING_URL}/images/create", timeout=30)
            if preload_response.status_code == 200:
                self.session.cookies.update(preload_response.cookies)
                self.log("Preloaded page, captured cookies")

            for rt in ["4", "3", None]:
                url = f"{BING_URL}/images/create?q={url_encoded_prompt}&FORM=GENCRE"
                if rt:
                    url += f"&rt={rt}"
                response = self._try_post_request(url, payload)
                if response:
                    redirect_url = response.headers["Location"].replace("&nfy=1", "")
                    request_id = redirect_url.split("id=")[-1]
                    self.session.get(f"{BING_URL}{redirect_url}")
                    polling_url = f"{BING_URL}/images/create/async/results/{request_id}?q={url_encoded_prompt}"
                    image_links = self._poll_images(polling_url)
                    return self._save_images(image_links, download_count)

            image_links = self._fallback_get_images(url_encoded_prompt)
            return self._save_images(image_links, download_count)

        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Network error: {str(e)}")

    def _save_images(self, links, download_count):
        """Save images to the output directory."""
        self.log(f"Downloading {min(download_count, len(links))} images to {self.output_dir}...")
        saved_files = []
        for i, link in enumerate(links[:download_count]):
            for attempt in range(3):
                try:
                    response = requests.get(link, timeout=30)
                    if response.status_code == 200:
                        filename = generate_filename(self.output_dir, i)
                        with open(filename, "wb") as f:
                            f.write(response.content)
                        self.log(f"✓ Saved {filename}", "success")
                        saved_files.append(filename)
                        break
                    else:
                        self.log(
                            f"⚠️ Attempt {attempt + 1}: Failed to download image {i}: "
                            f"HTTP {response.status_code}", "warning"
                        )
                except requests.exceptions.RequestException as e:
                    self.log(
                        f"⚠️ Attempt {attempt + 1}: Failed to download image {i}: {str(e)}", "warning"
                    )
                    if attempt == 2:
                        self.log(f"✗ Gave up on image {i} after 3 attempts", "error")
                    time.sleep(2)
        if len(saved_files) < download_count:
            self.log(
                f"⚠️ Only {len(saved_files)} images saved, less than requested {download_count}", "warning"
            )
        return saved_files

# --- Tkinter GUI Class ---

class BingImageGeneratorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pixel's DALL-E 3 Image Generator")
        self.root.geometry("900x750")
        self.root.minsize(800, 600)

        # Default theme: dark mode
        self.current_theme = "dark"

        # Set default output directory
        self.default_dir = "/storage/emulated/0/DCIM/BingImages" if os.name != "nt" else "BingImages"
        self.output_dir = tk.StringVar(value=self.default_dir)
        self.auth_cookie = tk.StringVar(value=DEFAULT_AUTH_COOKIE)
        self.download_count = tk.StringVar(value="4")
        self.status_var = tk.StringVar(value="Ready")

        # Store image references
        self.image_references = []
        self.generate_thread = None
        self.running_event = threading.Event()
        self.running_event.clear()

        # Create style object
        self.style = ttk.Style()

        # Setup default theme
        self.setup_dark_theme()

        # Create GUI elements
        self.create_widgets()

        # Bind window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_dark_theme(self):
        """Configure the dark mode theme using ttk.Style."""
        self.root.configure(bg="#000000")  # Full black background

        bg_color = "#000000"
        fg_color = "#FFFFFF"
        entry_bg = "#000000"
        button_bg = "#333333"
        button_fg = "#E0E0E0"
        scrollbar_track = "#242424"
        scrollbar_handle = "#666666"

        # Check if the "dark" theme already exists to avoid TclError
        if "dark" not in self.style.theme_names():
            self.style.theme_create("dark", parent="clam", settings={
                "TFrame": {"configure": {"background": bg_color}},
                "TLabel": {"configure": {"background": bg_color, "foreground": fg_color}},
                "TLabelFrame": {"configure": {"background": bg_color, "foreground": fg_color}},
                "TLabelFrame.Label": {"configure": {"background": bg_color, "foreground": fg_color}},
                "TButton": {
                    "configure": {
                        "background": button_bg,
                        "foreground": button_fg,
                        "padding": [8, 6],
                        "font": ("Helvetica", 12, "bold"),
                        "relief": "flat"
                    },
                    "map": {
                        "background": [("active", "#555555"), ("pressed", "#666666")],
                        "foreground": [("active", "#FFFFFF"), ("pressed", "#FFFFFF")]
                    }
                },
                "Elevated.TButton": {
                    "configure": {
                        "background": button_bg,
                        "foreground": button_fg,
                        "padding": [10, 8],
                        "font": ("Helvetica", 12, "bold"),
                        "relief": "flat",
                    },
                    "map": {
                        "background": [("active", "#555555"), ("pressed", "#666666")],
                        "foreground": [("active", "#FFFFFF"), ("pressed", "#FFFFFF")]
                    }
                },
                "TEntry": {
                    "configure": {
                        "fieldbackground": entry_bg,
                        "foreground": fg_color,
                        "insertcolor": fg_color,
                        "padding": [5, 5]
                    }
                },
                "TSpinbox": {
                    "configure": {
                        "fieldbackground": entry_bg,
                        "foreground": fg_color,
                        "padding": [5, 5],
                        "arrowsize": 15
                    }
                },
                "TNotebook": {
                    "configure": {"background": bg_color, "tabmargins": [5, 5, 0, 0]}
                },
                "TNotebook.Tab": {
                    "configure": {
                        "background": button_bg,
                        "foreground": fg_color,
                        "padding": [12, 8]
                    },
                    "map": {
                        "background": [("selected", "#444444")],
                        "foreground": [("selected", fg_color)]
                    }
                },
                "Vertical.TScrollbar": {
                    "configure": {
                        "background": scrollbar_track,
                        "troughcolor": scrollbar_track,
                        "arrowcolor": fg_color
                    },
                    "map": {
                        "background": [("active", scrollbar_handle)]
                    }
                }
            })
        self.style.theme_use("dark")

    def setup_light_theme(self):
        """Configure a clean light theme."""
        self.root.configure(bg="#f0f0f0")

        bg_color = "#f0f0f0"
        fg_color = "#000000"
        entry_bg = "#ffffff"
        button_bg = "#e0e0e0"
        button_fg = "#000000"
        scrollbar_track = "#d9d9d9"
        scrollbar_handle = "#a0a0a0"

        # Check if the "light" theme already exists to avoid TclError
        if "light" not in self.style.theme_names():
            self.style.theme_create("light", parent="clam", settings={
                "TFrame": {"configure": {"background": bg_color}},
                "TLabel": {"configure": {"background": bg_color, "foreground": fg_color}},
                "TLabelFrame": {"configure": {"background": bg_color, "foreground": fg_color}},
                "TLabelFrame.Label": {"configure": {"background": bg_color, "foreground": fg_color}},
                "TButton": {
                    "configure": {
                        "background": button_bg,
                        "foreground": button_fg,
                        "padding": [8, 6],
                        "font": ("Helvetica", 12, "bold"),
                        "relief": "flat"
                    },
                    "map": {
                        "background": [("active", "#c7c7c7"), ("pressed", "#b0b0b0")],
                        "foreground": [("active", "#000000"), ("pressed", "#000000")]
                    }
                },
                "Elevated.TButton": {
                    "configure": {
                        "background": button_bg,
                        "foreground": button_fg,
                        "padding": [10, 8],
                        "font": ("Helvetica", 12, "bold"),
                        "relief": "flat",
                    },
                    "map": {
                        "background": [("active", "#c7c7c7"), ("pressed", "#b0b0b0")],
                        "foreground": [("active", "#000000"), ("pressed", "#000000")]
                    }
                },
                "TEntry": {
                    "configure": {
                        "fieldbackground": entry_bg,
                        "foreground": fg_color,
                        "insertcolor": fg_color,
                        "padding": [5, 5]
                    }
                },
                "TSpinbox": {
                    "configure": {
                        "fieldbackground": entry_bg,
                        "foreground": fg_color,
                        "padding": [5, 5],
                        "arrowsize": 15
                    }
                },
                "TNotebook": {
                    "configure": {"background": bg_color, "tabmargins": [5, 5, 0, 0]}
                },
                "TNotebook.Tab": {
                    "configure": {
                        "background": button_bg,
                        "foreground": fg_color,
                        "padding": [12, 8]
                    },
                    "map": {
                        "background": [("selected", "#dcdcdc")],
                        "foreground": [("selected", fg_color)]
                    }
                },
                "Vertical.TScrollbar": {
                    "configure": {
                        "background": scrollbar_track,
                        "troughcolor": scrollbar_track,
                        "arrowcolor": fg_color
                    },
                    "map": {
                        "background": [("active", scrollbar_handle)]
                    }
                }
            })
        self.style.theme_use("light")

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header Frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            header_frame,
            text="Pixel's DALL-E 3 Image Generator",
            font=("Helvetica", 8, "bold")
        ).pack(side=tk.LEFT)

        ttk.Label(
            header_frame,
            text="v1.8.4",
            font=("Helvetica", 10)
        ).pack(side=tk.LEFT, padx=10)

        # Theme toggle button on header right
        theme_toggle_btn = ttk.Button(header_frame, text="☆", width=4, command=self.toggle_theme)
        theme_toggle_btn.pack(side=tk.RIGHT)

        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Image Prompt", padding=5)
        input_frame.pack(fill=tk.X, pady=5)
        self.prompt_entry = ttk.Entry(input_frame, font=("Helvetica", 10), width=50)
        self.prompt_entry.pack(fill=tk.X, pady=5)
        self.prompt_entry.bind("<Return>", lambda e: self.start_generation())

        # Settings section
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding=5)
        settings_frame.pack(fill=tk.X, pady=1)

        # Output directory
        dir_frame = ttk.Frame(settings_frame)
        dir_frame.pack(fill=tk.X, pady=5)
        ttk.Label(dir_frame, text="Output Directory:", width=15).pack(side=tk.LEFT)
        ttk.Entry(dir_frame, textvariable=self.output_dir).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=1)
        ttk.Button(dir_frame, text="Browse", command=self.browse_directory, style="Elevated.TButton").pack(side=tk.LEFT, padx=1)

        # Auth cookie
        cookie_frame = ttk.Frame(settings_frame)
        cookie_frame.pack(fill=tk.X, pady=5)
        ttk.Label(cookie_frame, text="Auth Cookie:", width=15).pack(side=tk.LEFT)
        self.cookie_entry = ttk.Entry(cookie_frame, textvariable=self.auth_cookie, show="*", width=29)
        self.cookie_entry.pack(side=tk.LEFT, fill=tk.X, expand=False)
        self.show_cookie = False
        self.cookie_toggle_btn = ttk.Button(
            cookie_frame,
            text="Show",
            command=self.toggle_cookie_visibility,
            width=7,
            style="Elevated.TButton"
        )
        self.cookie_toggle_btn.pack(side=tk.LEFT, padx=1)

        # Image count
        count_frame = ttk.Frame(settings_frame)
        count_frame.pack(fill=tk.X, pady=5)
        ttk.Label(count_frame, text="Images (1-4):", width=15).pack(side=tk.LEFT)
        ttk.Spinbox(count_frame, from_=1, to=4, textvariable=self.download_count, width=4).pack(side=tk.LEFT)

        # Action buttons frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        # Create a shadow label to simulate elevation
        self.generate_shadow = tk.Label(btn_frame, bg="#111111")
        self.generate_shadow.place(x=5, y=5, width=90, height=30)

        self.generate_btn = ttk.Button(
            btn_frame,
            text="Generate!",
            command=self.start_generation,
            width=12,
            style="Elevated.TButton"
        )
        self.generate_btn.pack(side=tk.LEFT, padx=5)

        self.stop_shadow = tk.Label(btn_frame, bg="#111111")
        self.stop_shadow.place(x=105, y=5, width=50, height=30)

        self.stop_btn = ttk.Button(
            btn_frame,
            text="Stop",
            command=self.stop_generation,
            width=6,
            state=tk.DISABLED,
            style="Elevated.TButton"
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        clear_shadow = tk.Label(btn_frame, bg="#111111")
        clear_shadow.place(x=165, y=5, width=90, height=30)

        ttk.Button(
            btn_frame,
            text="Clear Log",
            command=self.clear_log,
            width=12,
            style="Elevated.TButton"
        ).pack(side=tk.LEFT, padx=5)

        open_dir_shadow = tk.Label(btn_frame, bg="#111111")
        open_dir_shadow.place(x=265, y=5, width=90, height=30)

        ttk.Button(
            btn_frame,
            text="Open Dir",
            command=self.open_folder,
            width=12,
            style="Elevated.TButton"
        ).pack(side=tk.LEFT, padx=5)

        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Log tab
        log_frame = ttk.Frame(notebook, padding=5)
        notebook.add(log_frame, text="Log")

        self.log_text = tk.Text(
            log_frame,
            height=8,
            font=("Consolas", 10),
            wrap="word",
            bg="#000000" if self.current_theme == "dark" else "#FFFFFF",
            fg="#FFFFFF" if self.current_theme == "dark" else "#000000",
            insertbackground="#FFFFFF" if self.current_theme == "dark" else "#000000"
        )
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_text.configure(state=tk.DISABLED)

        # Results tab
        results_frame = ttk.Frame(notebook, padding=5)
        notebook.add(results_frame, text="Results")

        self.results_text = tk.Text(
            results_frame,
            height=5,
            font=("Consolas", 10),
            wrap="word",
            bg="#000000" if self.current_theme == "dark" else "#FFFFFF",
            fg="#FFFFFF" if self.current_theme == "dark" else "#000000",
            insertbackground="#FFFFFF" if self.current_theme == "dark" else "#000000"
        )
        scrollbar = ttk.Scrollbar(
            results_frame,
            orient=tk.VERTICAL,
            command=self.results_text.yview
        )
        self.results_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.results_text.configure(state=tk.DISABLED)

        # Preview tab
        preview_frame = ttk.Frame(notebook, padding=5)
        notebook.add(preview_frame, text="Image Preview")

        preview_container = ttk.Frame(preview_frame)
        preview_container.pack(fill=tk.BOTH, expand=True)

        self.preview_canvas = tk.Canvas(
            preview_container,
            bg="#000000" if self.current_theme == "dark" else "#FFFFFF",
            highlightthickness=0
        )
        scrollbar = ttk.Scrollbar(
            preview_container,
            orient=tk.VERTICAL,
            command=self.preview_canvas.yview
        )
        self.preview_canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.preview_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.image_frame = ttk.Frame(self.preview_canvas)
        self.canvas_frame = self.preview_canvas.create_window(
            (0, 0),
            window=self.image_frame,
            anchor="nw"
        )

        self.image_frame.bind("<Configure>", self.on_frame_configure)
        self.preview_canvas.bind("<Configure>", self.on_canvas_configure)

        # Status bar
        status_frame = ttk.Frame(main_frame, padding=(10, 5))
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Label(status_frame, text="Status:", width=7).pack(side=tk.LEFT)
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=2)

    def toggle_cookie_visibility(self):
        self.show_cookie = not self.show_cookie
        self.cookie_entry.configure(show="" if self.show_cookie else "*")
        self.cookie_toggle_btn.configure(text="Hide" if self.show_cookie else "Show")

    def on_frame_configure(self, event):
        """Reset the scroll region to encompass the inner frame."""
        self.preview_canvas.configure(scrollregion=self.preview_canvas.bbox("all"))

    def on_canvas_configure(self, event):
        """Update the width of the window inside the canvas."""
        self.preview_canvas.itemconfig(self.canvas_frame, width=event.width)

    def open_folder(self):
        """Open the output directory in file explorer."""
        dir_path = self.output_dir.get()
        if os.path.exists(dir_path):
            if os.name == 'nt':
                os.startfile(dir_path)
            elif os.name == 'posix':
                import subprocess
                try:
                    subprocess.Popen(['xdg-open', dir_path])
                except:
                    try:
                        subprocess.Popen(['open', dir_path])
                    except:
                        self.log_message("Unable to open folder automatically.", "warning")
        else:
            self.log_message(f"Directory does not exist: {dir_path}", "warning")

    def browse_directory(self):
        """Browse for output directory."""
        try:
            directory = filedialog.askdirectory()
            if directory:
                self.output_dir.set(directory)
                self.log_message(f"Output directory set to: {directory}", "success")
        except Exception as e:
            self.log_message(f"Error selecting directory: {str(e)}", "warning")

    def log_message(self, message, level="info"):
        """Add a message to the log text area."""
        tag = {
            "info": "info",
            "error": "error",
            "warning": "warning",
            "success": "success"
        }.get(level, "info")

        self.root.after(0, self._update_log, message, tag)

    def _update_log(self, message, tag):
        """Update the log text widget with throttling."""
        self.log_text.configure(state=tk.NORMAL)
        if self.log_text.index('end-1c') != '1.0':
            self.log_text.insert(tk.END, '\n')
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}", tag)

        self.log_text.tag_configure("error", foreground="#FF5555")  # Red for errors
        self.log_text.tag_configure("warning", foreground="#FFAA00")  # Orange for warnings
        self.log_text.tag_configure("success", foreground="#55FF55")  # Green for success
        self.log_text.tag_configure("info", foreground="#E0E0E0" if self.current_theme == "dark" else "#444444")  # Info color

        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.root.update_idletasks()

    def clear_log(self):
        """Clear the log and results areas."""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)

        self.results_text.configure(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.configure(state=tk.DISABLED)

        self.clear_previews()

    def update_status(self, status):
        """Update the status bar."""
        self.status_var.set(status)

    def start_generation(self):
        """Start image generation in a separate thread."""
        if self.running_event.is_set():
            return

        prompt = self.prompt_entry.get().strip()
        if not prompt:
            messagebox.showwarning("Warning", "Please enter an image description.")
            return

        try:
            download_count = int(self.download_count.get())
            if download_count < 1 or download_count > 4:
                raise ValueError("Download count must be between 1 and 4.")
        except ValueError:
            messagebox.showwarning("Warning", "Number of images must be between 1 and 4.")
            return

        self.running_event.set()
        self.generate_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.update_status("Generating...")

        self.generate_thread = threading.Thread(
            target=self.generate_images_thread,
            args=(prompt, download_count, self.output_dir.get(), self.auth_cookie.get())
        )
        self.generate_thread.daemon = True
        self.generate_thread.start()

    def stop_generation(self):
        """Signal to stop the image generation and wait for thread to terminate."""
        if not self.running_event.is_set():
            return
        self.running_event.clear()
        self.update_status("Stopping...")
        self.log_message("Stopping image generation. Please wait...", "warning")
        if self.generate_thread:
            self.generate_thread.join(timeout=2.0)
            self.generate_thread = None

    def generate_images_thread(self, prompt, download_count, output_dir, auth_cookie):
        """Run image generation in a separate thread."""
        try:
            generator = BingImageGenerator(
                auth_cookie=auth_cookie,
                output_dir=output_dir,
                logger_callback=self.log_message
            )

            saved_files = generator.generate_images(prompt, download_count)

            if not self.running_event.is_set():
                self.root.after(0, lambda: self.log_message("Generation cancelled.", "warning"))
                return

            self.root.after(0, self.update_results, saved_files)
            self.root.after(0, lambda: self.log_message(f"✓ Successfully saved {len(saved_files)} images.", "success"))

        except Exception as e:
            if self.running_event.is_set():
                self.root.after(0, lambda: self.log_message(f"✗ Error: {str(e)}", "error"))
                self.root.after(0, self.update_status, "Error")
        finally:
            self.root.after(0, self._reset_ui)

    def _reset_ui(self):
        """Reset UI elements after generation."""
        self.running_event.clear()
        self.generate_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.update_status("Ready")
        self.prompt_entry.focus_set()

    def update_results(self, saved_files):
        """Update the results text area with saved file paths."""
        self.results_text.configure(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)

        if saved_files:
            self.results_text.insert(tk.END, "Generated Images:\n")
            for file in saved_files:
                self.results_text.insert(tk.END, f"- {file}\n")
            self.display_image_previews(saved_files)
        else:
            self.results_text.insert(tk.END, "No images were generated.")

        self.results_text.configure(state=tk.DISABLED)
        self.prompt_entry.delete(0, tk.END)
        self.prompt_entry.focus_set()

    def clear_previews(self):
        """Clear image previews and release resources."""
        for widget in self.image_frame.winfo_children():
            widget.destroy()
        self.image_references = []
        import gc
        gc.collect()

    def enlarge_image(self, file_path):
        """Display the full-size image in a new window optimized for mobile."""
        try:
            enlarge_window = tk.Toplevel(self.root)
            enlarge_window.title(os.path.basename(file_path))
            enlarge_window.configure(bg="#000000" if self.current_theme == "dark" else "#FFFFFF")

            # Apply current theme styles
            if self.current_theme == "dark":
                style = ttk.Style(enlarge_window)
                style.theme_use("dark")
            else:
                style = ttk.Style(enlarge_window)
                style.theme_use("light")

            # Screen dimensions setup
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()

            window_width = int(screen_width * 0.9)
            window_height = int(screen_height * 0.9)

            x_offset = (screen_width - window_width) // 2
            y_offset = (screen_height - window_height) // 2

            enlarge_window.geometry(f"{window_width}x{window_height}+{x_offset}+{y_offset}")
            enlarge_window.minsize(300, 400)
            enlarge_window.resizable(True, True)

            img = Image.open(file_path)
            width, height = img.size

            max_width = window_width
            max_height = window_height - 60
            if width > max_width or height > max_height:
                ratio = min(max_width / width, max_height / height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                img = img.resize((new_width, new_height), Image.LANCZOS)

            tk_img = ImageTk.PhotoImage(img)
            self.image_references.append(tk_img)

            frame = ttk.Frame(enlarge_window)
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            img_label = ttk.Label(frame, image=tk_img)
            img_label.pack(pady=5, expand=True)

            ttk.Button(
                frame,
                text="Close",
                command=enlarge_window.destroy,
                width=15
            ).pack(pady=10)

            enlarge_window.option_add("*TButton*Font", "Helvetica 14")

        except Exception as e:
            self.log_message(f"Error enlarging image {file_path}: {str(e)}", "error")

    def display_image_previews(self, file_paths):
        """Display image previews in the preview tab with tap-to-enlarge."""
        self.clear_previews()
        max_width = 250

        for i, file_path in enumerate(file_paths):
            try:
                img_container = ttk.Frame(self.image_frame, padding=5)
                img_container.pack(fill=tk.X, pady=10)

                img = Image.open(file_path)
                width, height = img.size
                if width > max_width:
                    ratio = max_width / width
                    new_width = max_width
                    new_height = int(height * ratio)
                    img = img.resize((new_width, new_height), Image.LANCZOS)

                tk_img = ImageTk.PhotoImage(img)
                self.image_references.append(tk_img)

                img_label = ttk.Label(img_container, image=tk_img)
                img_label.pack()

                img_label.bind("<Button-1>", lambda event, path=file_path: self.enlarge_image(path))

                filename = os.path.basename(file_path)
                ttk.Label(
                    img_container,
                    text=filename,
                    font=("Helvetica", 10)
                ).pack(pady=5)

                ttk.Button(
                    img_container,
                    text="Open",
                    command=lambda path=file_path: self.open_image(path),
                    width=12,
                    style="Elevated.TButton"
                ).pack()

            except Exception as e:
                self.log_message(f"Error loading preview for {file_path}: {str(e)}", "error")

    def open_image(self, file_path):
        """Open the image file with the default system viewer."""
        if os.path.exists(file_path):
            if os.name == 'nt':
                os.startfile(file_path)
            elif os.name == 'posix':
                import subprocess
                try:
                    subprocess.Popen(['xdg-open', file_path])
                except:
                    try:
                        subprocess.Popen(['open', file_path])
                    except:
                        self.log_message("Unable to open image automatically.", "warning")
        else:
            self.log_message(f"File does not exist: {file_path}", "warning")

    def on_closing(self):
        """Handle window close."""
        if self.running_event.is_set():
            self.stop_generation()
            self.root.after(1000, self.root.destroy)
        else:
            self.root.destroy()

    def toggle_theme(self):
        """Toggle between dark and light themes."""
        if self.current_theme == "dark":
            self.setup_light_theme()
            self.current_theme = "light"
        else:
            self.setup_dark_theme()
            self.current_theme = "dark"

        # Update widget colors for text widgets and canvas backgrounds
        bg_color = "#000000" if self.current_theme == "dark" else "#FFFFFF"
        fg_color = "#FFFFFF" if self.current_theme == "dark" else "#000000"

        self.log_text.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        self.results_text.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        self.preview_canvas.configure(bg=bg_color)

        # Update status bar color if needed
        # Force refresh the window to update styles
        self.root.update_idletasks()

        # Also update buttons' shadows to fit theme
        shadow_color = "#111111" if self.current_theme == "dark" else "#bbbbbb"
        for shadow in [self.generate_shadow, self.stop_shadow]:
            shadow.configure(bg=shadow_color)

# --- Main Application ---

def main():
    try:
        root = tk.Tk()
        app = BingImageGeneratorGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Error initializing GUI: {str(e)}")
        print("Please run this script in Pydroid 3's editor, not the terminal.")

if __name__ == "__main__":
    main()
