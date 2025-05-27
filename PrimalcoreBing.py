#!/usr/bin/env python3
# =====================================
# Script:     Bing Image Generator
# Author:     Primal Core
# Version:    1.9.7
# Description: Fetches AI-generated images from Bing using a prompt and saves them to a directory.
# License:    MIT
# Dependencies: requests, rich, tkinter, pillow
# Notes:      Run this script in Pydroid 3's editor, not the terminal/REPL.
#             Tap image previews to enlarge them. Enlarged view optimized for mobile.
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
    """Raised when the authentication cookie is invalid or access denied."""
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
        self.root.title("Pixel's DALL-E 3 Generator")

        # Optimize window size for Android
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        window_width = int(screen_width * 0.95)
        window_height = int(screen_height * 0.85)
        x_offset = (screen_width - window_width) // 2
        y_offset = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x_offset}+{y_offset}")
        self.root.minsize(400, 600)

        # Set default output directory
        self.default_dir = "/storage/emulated/0/DCIM/BingImages"
        self.output_dir = tk.StringVar(value=self.default_dir)
        self.auth_cookie = tk.StringVar(value=DEFAULT_AUTH_COOKIE)
        self.download_count = tk.StringVar(value="4")
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.show_cookie = False
        self.current_theme = tk.StringVar(value="classic")  # Default theme

        # Store image references
        self.image_references = []
        self.generate_thread = None
        self.running_event = threading.Event()
        self.running_event.clear()

        # Set initial theme
        self.style = ttk.Style()
        self.style.theme_use(self.current_theme.get())

        # Configure default styles
        self.configure_default_styles()

        # Create GUI elements
        self.create_widgets()

        # Bind window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def configure_default_styles(self):
        """Configure default styles for a less flat appearance."""
        # General button style
        self.style.configure('TButton',
                            font=('Segoe UI', 10, 'bold'),
                            padding=[10, 6],
                            relief='raised',
                            borderwidth=2)
        self.style.map('TButton',
                      background=[('active', '#e0e0e0'), ('pressed', '#c0c0c0')],
                      foreground=[('active', '#000000'), ('pressed', '#000000')])

        # Accent button style (Generate, Open Folder)
        self.style.configure('Accent.TButton',
                            font=('Segoe UI', 10, 'bold'),
                            padding=[12, 8],
                            relief='raised',
                            borderwidth=2,
                            background='#4CAF50',
                            foreground='#FFFFFF')
        self.style.map('Accent.TButton',
                      background=[('active', '#43A047'), ('pressed', '#388E3C')],
                      foreground=[('active', '#FFFFFF'), ('pressed', '#FFFFFF')])

        # LabelFrame and Frame
        self.style.configure('TLabelFrame', padding=8)
        self.style.configure('TFrame', padding=4)

        # Progressbar
        self.style.configure('TProgressbar',
                            thickness=6,
                            troughcolor='#d0d0d0',
                            background='#0288D1')

    def create_widgets(self):
        """Create and layout GUI widgets with a modern, raised design."""
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header Frame (Vertical Stack with Theme Toggle)
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            header_frame,
            text="Pixel's DALL-E 3 Generator",
            font=("Segoe UI", 12, "bold")
        ).pack()

        ttk.Label(
            header_frame,
            text="v1.9.7",
            font=("Segoe UI", 8)
        ).pack()

        self.theme_btn = ttk.Button(
            header_frame,
            text=f"Toggle Theme ({self.current_theme.get().capitalize()})",
            command=self.toggle_theme,
            width=20
        )
        self.theme_btn.pack(pady=5)
        self.create_tooltip(self.theme_btn, "Switch between Classic and Clam themes.")

        # Input Section
        input_frame = ttk.LabelFrame(main_frame, text="Image Prompt", padding=10)
        input_frame.pack(fill=tk.X, pady=10)

        self.prompt_entry = ttk.Entry(input_frame, font=("Segoe UI", 12), width=40)
        self.prompt_entry.pack(fill=tk.X, pady=5)
        self.prompt_entry.bind("<Return>", lambda e: self.start_generation())
        self.prompt_entry.insert(0, "Description here...")
        self.prompt_entry.bind("<FocusIn>", self.clear_placeholder)
        self.prompt_entry.bind("<FocusOut>", self.restore_placeholder)
        self.create_tooltip(self.prompt_entry, "Enter a detailed description for the image you want to generate.")

        # Settings Section
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding=10)
        settings_frame.pack(fill=tk.X, pady=10)

        settings_grid = ttk.Frame(settings_frame)
        settings_grid.pack(fill=tk.X)

        # Output directory
        ttk.Label(settings_grid, text="Directory:", font=("Segoe UI", 10)).grid(row=0, column=0, sticky="w", padx=8, pady=8)
        dir_entry = ttk.Entry(settings_grid, textvariable=self.output_dir, width=25, font=("Segoe UI", 10))
        dir_entry.grid(row=0, column=1, sticky="ew", padx=8, pady=8)
        ttk.Button(
            settings_grid,
            text="Browse",
            command=self.browse_directory,
            width=8
        ).grid(row=0, column=2, padx=8, pady=8)
        self.create_tooltip(dir_entry, "")

        # Auth cookie
        ttk.Label(settings_grid, text="Auth Cookie:", font=("Segoe UI", 10)).grid(row=1, column=0, sticky="w", padx=8, pady=8)
        self.cookie_entry = ttk.Entry(settings_grid, textvariable=self.auth_cookie, show="▪︎", width=25, font=("Segoe UI", 10))
        self.cookie_entry.grid(row=1, column=1, sticky="ew", padx=8, pady=8)
        self.cookie_toggle_btn = ttk.Button(
            settings_grid,
            text="Show",
            command=self.toggle_cookie_visibility,
            width=8
        )
        self.cookie_toggle_btn.grid(row=1, column=2, padx=8, pady=8)
        self.create_tooltip(self.cookie_entry, "Enter your Bing authentication cookie.")

        # Image count
        ttk.Label(settings_grid, text="Images (1-4):", font=("Segoe UI", 10)).grid(row=2, column=0, sticky="w", padx=8, pady=8)
        ttk.Spinbox(
            settings_grid,
            from_=1,
            to=4,
            textvariable=self.download_count,
            width=5,
            font=("Segoe UI", 10)
        ).grid(row=2, column=1, sticky="w", padx=8, pady=8)
        self.create_tooltip(settings_grid.winfo_children()[-1], "Number of images to generate (1-4).")

        settings_grid.columnconfigure(1, weight=1)

        # Action Buttons (Single Row)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        self.generate_btn = ttk.Button(
            btn_frame,
            text="Generate",
            command=self.start_generation,
            width=10,
            style="Accent.TButton"
        )
        self.generate_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.generate_btn, "Start generating images based on the prompt.")

        self.stop_btn = ttk.Button(
            btn_frame,
            text="Stop",
            command=self.stop_generation,
            width=8
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.stop_btn, "Stop the current image generation process.")

        ttk.Button(
            btn_frame,
            text="Clear",
            command=self.clear_log,
            width=8
        ).pack(side=tk.LEFT, padx=5)
        self.create_tooltip(btn_frame.winfo_children()[-1], "Clear the log and results.")
        # Progress Bar
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=200,
            mode="determinate"
        ).pack(side=tk.LEFT, padx=10)
        ttk.Label(progress_frame, textvariable=self.status_var, font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=10)

        # Notebook for Tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)

        # Log Tab
        log_frame = ttk.Frame(notebook, padding=8)
        notebook.add(log_frame, text="Log")

        self.log_text = tk.Text(
            log_frame,
            height=6,
            font=("Consolas", 10),
            wrap="word",
            borderwidth=0
        )
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_text.configure(state=tk.DISABLED)

        # Results Tab
        results_frame = ttk.Frame(notebook, padding=8)
        notebook.add(results_frame, text="Results")

        self.results_text = tk.Text(
            results_frame,
            height=4,
            font=("Consolas", 10),
            wrap="word",
            borderwidth=0
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

        # Preview Tab
        preview_frame = ttk.Frame(notebook, padding=8)
        notebook.add(preview_frame, text="Image Preview")

        preview_container = ttk.Frame(preview_frame)
        preview_container.pack(fill=tk.BOTH, expand=True)

        self.preview_canvas = tk.Canvas(
            preview_container,
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

        # Initialize focus
        self.prompt_entry.focus_set()

    def toggle_theme(self):
        """Toggle between 'classic' and 'clam' themes."""
        current = self.current_theme.get()
        new_theme = 'clam' if current == 'classic' else 'classic'
        self.style.theme_use(new_theme)
        self.current_theme.set(new_theme)
        self.theme_btn.config(text=f"Toggle Theme ({new_theme.capitalize()})")

        # Update text colors to match the new theme
        bg_color = self.style.lookup('TFrame', 'background')
        fg_color = self.style.lookup('TLabel', 'foreground')
        self.log_text.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        self.results_text.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        self.preview_canvas.configure(bg=bg_color)

    def create_tooltip(self, widget, text):
        """Create a tooltip for a widget."""
        def enter(event):
            try:
                x, y = widget.winfo_rootx() + 25, widget.winfo_rooty() + 25
                self.tooltip = tk.Toplevel(widget)
                self.tooltip.wm_overrideredirect(True)
                self.tooltip.wm_geometry(f"+{x}+{y}")
                label = ttk.Label(
                    self.tooltip,
                    text=text,
                    background="#FFFF99",
                    foreground="#212121",
                    padding=(5, 2),
                    relief="solid",
                    borderwidth=1,
                    font=("Segoe UI", 8)
                )
                label.pack()
            except Exception as e:
                self.log_message(f"Error creating tooltip: {str(e)}", "warning")

        def leave(event):
            if hasattr(self, "tooltip"):
                self.tooltip.destroy()
                del self.tooltip

        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def clear_placeholder(self, event):
        """Clear placeholder text when entry gains focus."""
        if self.prompt_entry.get() == "Description here...":
            self.prompt_entry.delete(0, tk.END)

    def restore_placeholder(self, event):
        """Restore placeholder text if entry is empty."""
        if not self.prompt_entry.get():
            self.prompt_entry.insert(0, "Description here...")

    def toggle_cookie_visibility(self):
        """Toggle visibility of the auth cookie."""
        self.show_cookie = not self.show_cookie
        self.cookie_entry.configure(show="" if self.show_cookie else "▪︎")
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
            try:
                import subprocess
                subprocess.Popen(["xdg-open", dir_path])
            except:
                try:
                    subprocess.Popen(["open", dir_path])
                except:
                    self.log_message("Unable to open folder automatically.", "warning")
        else:
            self.log_message(f"Directory does not exist: {dir_path}", "warning")

    def browse_directory(self):
        """Browse for output directory."""
        try:
            directory = filedialog.askdirectory(initialdir=self.output_dir.get())
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
        """Update the log text widget."""
        self.log_text.configure(state=tk.NORMAL)
        if self.log_text.index("end-1c") != "1.0":
            self.log_text.insert(tk.END, "\n")
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}", tag)

        self.log_text.tag_configure("error", foreground="#FF5252")
        self.log_text.tag_configure("warning", foreground="#FFB300")
        self.log_text.tag_configure("success", foreground="#4CAF50")
        self.log_text.tag_configure("info", foreground=self.style.lookup('TLabel', 'foreground'))

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
        self.progress_var.set(0.0)

    def update_status(self, status):
        """Update the status bar."""
        self.status_var.set(status)

    def update_progress(self, value):
        """Update the progress bar."""
        self.progress_var.set(value)
        self.root.update_idletasks()

    def start_generation(self):
        """Start image generation in a separate thread."""
        if self.running_event.is_set():
            return

        prompt = self.prompt_entry.get().strip()
        if not prompt or prompt == "Description here...":
            messagebox.showwarning("Warning", "Please enter a valid image description.")
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
        self.update_progress(10)

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

            # Simulate progress updates
            self.root.after(0, self.update_progress, 20)
            saved_files = generator.generate_images(prompt, download_count)
            self.root.after(0, self.update_progress, 80)

            if not self.running_event.is_set():
                self.root.after(0, lambda: self.log_message("Generation cancelled.", "warning"))
                return

            self.root.after(0, self.update_results, saved_files)
            self.root.after(0, self.update_progress, 100)
            self.root.after(0, lambda: self.log_message(f"Successfully saved {len(saved_files)} images.", "success"))

        except Exception as e:
            if self.running_event.is_set():
                self.root.after(0, lambda: self.log_message(f"Error: {str(e)}", "error"))
                self.root.after(0, self.update_status, "Error")
                self.root.after(0, self.update_progress, 0)
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
        if self.prompt_entry.get() != "Description here...":
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
        """Display the full-size image in a new window with size matching the image."""
        try:
            enlarge_window = tk.Toplevel(self.root)
            enlarge_window.title(os.path.basename(file_path))

            # Apply current theme to the new window
            style = ttk.Style(enlarge_window)
            style.theme_use(self.current_theme.get())

            # Get screen dimensions
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()

            # Load and resize image to fit within screen bounds
            img = Image.open(file_path)
            width, height = img.size
            max_width = screen_width - 20  # Small padding
            max_height = screen_height - 60  # Account for button and padding
            if width > max_width or height > max_height:
                ratio = min(max_width / width, max_height / height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                img = img.resize((new_width, new_height), Image.LANCZOS)
            else:
                new_width, new_height = width, height

            tk_img = ImageTk.PhotoImage(img)
            self.image_references.append(tk_img)

            # Create frame and widgets
            frame = ttk.Frame(enlarge_window)
            frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            img_label = ttk.Label(frame, image=tk_img)
            img_label.pack(pady=5)

            close_btn = ttk.Button(
                frame,
                text="Close",
                command=enlarge_window.destroy,
                style="Accent.TButton",
                width=10
            )
            close_btn.pack(pady=5)

            # Update the window to get the button's height
            enlarge_window.update_idletasks()

            # Calculate window size based on image and button
            window_width = new_width + 10  # Small padding
            window_height = new_height + close_btn.winfo_reqheight() + 20  # Button height + padding

            # Ensure window isn't smaller than minimum size
            window_width = max(window_width, 200)  # Minimum width for usability
            window_height = max(window_height, 200)  # Minimum height for usability

            # Center the window on screen
            x_offset = (screen_width - window_width) // 2
            y_offset = (screen_height - window_height) // 2
            enlarge_window.geometry(f"{window_width}x{window_height}+{x_offset}+{y_offset}")

            enlarge_window.resizable(False, False)  # Prevent resizing

        except Exception as e:
            self.log_message(f"Error enlarging image {file_path}: {str(e)}", "error")

    def display_image_previews(self, file_paths):
        """Display image previews in the preview tab with tap-to-enlarge."""
        self.clear_previews()
        max_width = 250  # Reduced for mobile screens
        columns = 1 if self.preview_canvas.winfo_width() < 600 else max(1, self.preview_canvas.winfo_width() // (max_width + 20))

        for i, file_path in enumerate(file_paths):
            try:
                img_container = ttk.Frame(self.image_frame)
                img_container.grid(row=i // columns, column=i % columns, padx=8, pady=8, sticky="n")

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
                self.create_tooltip(img_label, "Tap to enlarge the image.")

                filename = os.path.basename(file_path)
                ttk.Label(
                    img_container,
                    text=filename,
                    font=("Segoe UI", 8),
                    wraplength=int(max_width)
                ).pack(pady=5)

            except Exception as e:
                self.log_message(f"Error loading preview for {file_path}: {str(e)}", "error")

    def on_closing(self):
        """Handle window close."""
        if self.running_event.is_set():
            self.stop_generation()
            self.root.after(1000, self.root.destroy)
        else:
            self.root.destroy()

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
