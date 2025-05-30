#!/usr/bin/env python3
# --- Script Details ---
# Script:     Pixel's DALL-E Image Generator CLI
# Author:     Primal Core
# Version:    2.0.1
# Description: Advanced CLI tool for generating AI images with interactive style variations.
# License:    MIT
# Dependencies: requests, rich, Pillow
# Usage:      Access the interactive help menu (option 10) for detailed guidance.

import os
import random
import re
import time
import logging
import argparse
import glob
import subprocess
import platform
from urllib.parse import quote
from http.cookies import SimpleCookie
import requests
from PIL import Image
from io import BytesIO

try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.progress import Progress
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt, Confirm
    console = Console()
except ImportError:
    print("Error: Required libraries ('rich', 'Pillow') are not installed. Please run 'pip install rich Pillow'.")
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

# --- Exceptions ---
class PixelDalleGenError(Exception):
    """Base exception for Pixel's DALL-E Image Generator errors."""
    pass

class BlockedPromptError(PixelDalleGenError):
    """Raised when the prompt contains sensitive words."""
    pass

class NetworkError(PixelDalleGenError):
    """Raised when a network-related error occurs."""
    pass

# --- Utility Functions ---
def parse_cookie_string(cookie_string):
    """Parse a cookie string into a dictionary."""
    cookie = SimpleCookie()
    cookie.load(cookie_string)
    return {key: morsel.value for key, morsel in cookie.items()}

def setup_logging(log_level="INFO"):
    """Configure logging to console and file."""
    log_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[RichHandler(console=console), logging.FileHandler(LOG_FILE)]
    )
    return logging.getLogger("pixel_dalle_gen")

def load_config():
    """Load settings from config file if it exists."""
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
    """Save settings to config file."""
    with open(CONFIG_FILE, "w") as f:
        f.write(f"cookie={cookie}\n")
        f.write(f"output_dir={output_dir}\n")
        f.write(f"custom_styles={','.join(custom_styles)}\n")

def create_directory(output_dir):
    """Create the output directory if it doesn't exist."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        console.print(f"[green]Created directory: {output_dir}[/green]")
    if not os.access(output_dir, os.W_OK):
        raise PermissionError(f"Output directory '{output_dir}' is not writable.")

def generate_filename(output_dir, index, style=None, file_format='png'):
    """Generate a unique filename for an image, including style if provided."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    style_part = f"_{style.replace(' ', '_')}" if style else ""
    return os.path.join(output_dir, f"pixel_image{style_part}_{timestamp}_{index}.{file_format}")

def contains_sensitive_words(prompt):
    """Check if the prompt contains sensitive words."""
    prompt_lower = prompt.lower()
    for word in SENSITIVE_WORDS:
        if word in prompt_lower:
            return True, word
    return False, None

def read_prompts_file(file_path):
    """Read prompts from a file, one per line, ignoring empty lines."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Prompt file '{file_path}' not found.")
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def retry_request(func, max_attempts=3, base_delay=2):
    """Retry a request with exponential backoff."""
    for attempt in range(max_attempts):
        try:
            return func()
        except NetworkError as e:
            if attempt == max_attempts - 1:
                raise
            delay = base_delay * (2 ** attempt)
            console.print(f"[yellow]Attempt {attempt + 1} failed: {str(e)}. Retrying in {delay}s...[/yellow]")
            time.sleep(delay)

def generate_thumbnails(config, generator):
    """Generate thumbnails for selected images with customizable options."""
    image_extensions = ["*.png", "*.jpg", "*.jpeg"]
    image_files = []
    for ext in image_extensions:
        image_files.extend(glob.glob(os.path.join(config["output_dir"], ext)))
    
    if not image_files:
        console.print("[yellow]No images found in output directory.[/yellow]")
        return
    
    console.print(f"[bold cyan]Found {len(image_files)} images. Select images for thumbnail generation.[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Number", style="cyan", width=8)
    table.add_column("Filename", style="white")
    for i, image_path in enumerate(image_files, 1):
        table.add_row(str(i), os.path.basename(image_path))
    console.print(table)
    
    selection = Prompt.ask(
        "[bold green]Enter image numbers (e.g., '1,3,5'), 'all', or press Enter to cancel[/bold green]",
        default=""
    ).strip().lower()
    if not selection:
        console.print("[yellow]Thumbnail generation cancelled.[/yellow]")
        return
    
    if selection == "all":
        selected_files = image_files
    else:
        try:
            indices = [int(i) - 1 for i in selection.split(",") if i.strip().isdigit()]
            selected_files = [image_files[i] for i in indices if 0 <= i < len(image_files)]
        except ValueError:
            console.print("[red]Invalid selection. Cancelling.[/red]")
            return
    
    thumb_size = IntPrompt.ask(
        "[bold green]Enter thumbnail size (pixels, e.g., 128 for 128x128)[/bold green]",
        default=128
    )
    thumb_format = Prompt.ask(
        "[bold green]Enter thumbnail format (png/jpg)[/bold green]",
        choices=["png", "jpg"],
        default="png"
    )
    thumb_dir = os.path.join(config["output_dir"], "thumbnails")
    create_directory(thumb_dir)
    
    overwrite = Confirm.ask(
        "[yellow]Overwrite existing thumbnails if they exist?[/yellow]",
        default=False
    )
    
    if not Confirm.ask(
        f"[bold yellow]Generate {len(selected_files)} thumbnails (size: {thumb_size}x{thumb_size}, format: {thumb_format}) "
        f"in {thumb_dir}?[/bold yellow]",
        default=True
    ):
        console.print("[yellow]Thumbnail generation cancelled.[/yellow]")
        return
    
    generated = 0
    skipped = 0
    failed = 0
    console.print(f"[bold cyan]Generating {len(selected_files)} thumbnails...[/bold cyan]")
    with Progress() as progress:
        task = progress.add_task("[cyan]Generating thumbnails...", total=len(selected_files))
        for image_path in selected_files:
            thumb_filename = f"{os.path.splitext(os.path.basename(image_path))[0]}_thumb.{thumb_format}"
            thumb_path = os.path.join(thumb_dir, thumb_filename)
            
            if os.path.exists(thumb_path) and not overwrite:
                console.print(f"[yellow]Skipped existing thumbnail: {thumb_filename}[/yellow]")
                skipped += 1
                progress.update(task, advance=1)
                continue
            
            try:
                generator.create_thumbnail(image_path, thumb_path, size=(thumb_size, thumb_size), output_format=thumb_format)
                console.print(f"[green]Generated: {thumb_filename}[/green]")
                generated += 1
            except (Image.UnidentifiedImageError, PermissionError, ValueError) as e:
                console.print(f"[red]Failed to generate thumbnail for {os.path.basename(image_path)}: {str(e)}[/red]")
                generator.log(f"Thumbnail error for {image_path}: {str(e)}", "error")
                failed += 1
            progress.update(task, advance=1)
    
    console.print(f"\n[bold green]Thumbnail Generation Summary:[/bold green]")
    console.print(f"[green]Generated: {generated}[/green]")
    console.print(f"[yellow]Skipped: {skipped}[/yellow]")
    console.print(f"[red]Failed: {failed}[/red]")
    generator.log(f"Thumbnail generation: {generated} generated, {skipped} skipped, {failed} failed", "info")

def list_generated_images(output_dir):
    """List all images in the output directory with details."""
    image_extensions = ["*.png", "*.jpg", "*.jpeg"]
    image_files = []
    for ext in image_extensions:
        image_files.extend(glob.glob(os.path.join(output_dir, ext)))
    
    if not image_files:
        console.print("[yellow]No images found in output directory.[/yellow]")
        return
    
    table = Table(title="[bold cyan]Generated Images[/bold cyan]", show_header=True, header_style="bold magenta")
    table.add_column("Filename", style="cyan")
    table.add_column("Style", style="white")
    table.add_column("Creation Time", style="white")
    
    for image_path in image_files:
        filename = os.path.basename(image_path)
        style_match = re.search(r'pixel_image_([^_]+)_[\d_]+\.\w+', filename)
        style = style_match.group(1).replace('_', ' ') if style_match else "None"
        creation_time = time.ctime(os.path.getctime(image_path))
        table.add_row(filename, style, creation_time)
    
    console.print(table)

def clear_output_directory(output_dir, logger):
    """Delete all images in the output directory."""
    image_extensions = ["*.png", "*.jpg", "*.jpeg"]
    image_files = []
    for ext in image_extensions:
        image_files.extend(glob.glob(os.path.join(output_dir, ext)))
    
    if not image_files:
        console.print("[yellow]No images found in output directory.[/yellow]")
        return
    
    if Confirm.ask(f"[bold yellow]Delete {len(image_files)} images in {output_dir}?[/bold yellow]", default=False):
        with Progress() as progress:
            task = progress.add_task("[cyan]Deleting images...", total=len(image_files))
            for image_path in image_files:
                try:
                    os.remove(image_path)
                    console.print(f"[green]Deleted: {os.path.basename(image_path)}[/green]")
                    logger.info(f"Deleted image: {image_path}")
                except Exception as e:
                    console.print(f"[red]Error deleting {os.path.basename(image_path)}: {str(e)}[/red]")
                    logger.error(f"Error deleting {image_path}: {str(e)}")
                progress.update(task, advance=1)

def preview_images(output_dir):
    """Open images in the default image viewer."""
    image_extensions = ["*.png", "*.jpg", "*.jpeg"]
    image_files = []
    for ext in image_extensions:
        image_files.extend(glob.glob(os.path.join(output_dir, ext)))
    
    if not image_files:
        console.print("[yellow]No images found in output directory.[/yellow]")
        return
    
    console.print(f"[bold cyan]Found {len(image_files)} images. Select images to preview.[/bold cyan]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Number", style="cyan", width=8)
    table.add_column("Filename", style="white")
    
    for i, image_path in enumerate(image_files, 1):
        table.add_row(str(i), os.path.basename(image_path))
    console.print(table)
    
    selection = Prompt.ask("[bold green]Enter image numbers (e.g., '1,3,5'), 'all', or press Enter to cancel[/bold green]").strip().lower()
    if not selection:
        console.print("[yellow]Preview cancelled.[/yellow]")
        return
    
    if selection == "all":
        selected_files = image_files
    else:
        try:
            indices = [int(i) - 1 for i in selection.split(",") if i.strip().isdigit()]
            selected_files = [image_files[i] for i in indices if 0 <= i < len(image_files)]
        except ValueError:
            console.print("[red]Invalid input. Preview cancelled.[/red]")
            return
    
    system = platform.system()
    for image_path in selected_files:
        try:
            if system == "Windows":
                os.startfile(image_path)
            elif system == "Darwin":
                subprocess.run(["open", image_path])
            elif system == "Linux":
                subprocess.run(["xdg-open", image_path])
            else:
                console.print(f"[yellow]Preview not supported on {system}.[/yellow]")
                return
            console.print(f"[green]Opened: {os.path.basename(image_path)}[/green]")
        except Exception as e:
            console.print(f"[red]Error opening {os.path.basename(image_path)}: {str(e)}[/red]")

# --- Core Image Generator Class ---
class PixelDalleGenerator:
    """A class to generate and save AI-generated images."""
    def __init__(self, auth_cookie, output_dir, logger):
        """Initialize with authentication cookie and output directory."""
        self.auth_cookie = auth_cookie
        self.output_dir = os.path.abspath(output_dir)
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.cookies.update(parse_cookie_string(self.auth_cookie))
        create_directory(self.output_dir)

    def log(self, message, level="info"):
        """Log a message with the specified level."""
        getattr(self.logger, level.lower())(message)

    def test_cookie(self):
        """Test if the authentication cookie is valid."""
        try:
            response = retry_request(lambda: self.session.get(f"{BING_URL}/images/create", timeout=30))
            if response.status_code == 200 and "create" in response.url:
                self.session.cookies.update(response.cookies)
                self.log("Cookie is valid!", "info")
                return True
            raise NetworkError(f"Invalid cookie or access denied: Status {response.status_code}")
        except NetworkError as e:
            raise NetworkError(f"Cookie test failed: {str(e)}")

    def _try_post_request(self, url, payload):
        """Attempt a POST request and return response if successful."""
        def request():
            response = self.session.post(url, allow_redirects=False, data=payload, timeout=600)
            if "this prompt has been blocked" in response.text.lower():
                raise BlockedPromptError(ERROR_BLOCKED_PROMPT)
            return response if response.status_code == 302 else None
        return retry_request(request)

    def _fallback_get_images(self, url_encoded_prompt):
        """Fallback to GET request and parse HTML for images or redirects."""
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
                payload = f"q={url_encoded_prompt}&qs=ds"
                response = self.session.post(url, allow_redirects=False, data=payload, timeout=600)
                if response.status_code == 302:
                    redirect_url = response.headers["Location"].replace("&nfy=1", "")
                    request_id = redirect_url.split("id=")[-1]
                    self.session.get(f"{BING_URL}{redirect_url}")
                    polling_url = f"{BING_URL}/images/create/async/results/{request_id}?q={url_encoded_prompt}"
                    return self._poll_images(polling_url, images_per_style=4)

            raise NetworkError(ERROR_REDIRECT)
        return retry_request(request)

    def _poll_images(self, polling_url, images_per_style):
        """Poll for image links with timeout, reporting only the requested number."""
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
                        console.print(f"[green]Using {num_images} image{'s' if num_images != 1 else ''} for this style[/green]")
                        return links
                time.sleep(1)
            except requests.exceptions.RequestException:
                time.sleep(2)
        raise NetworkError(ERROR_TIMEOUT)

    def generate_images(self, prompt, styles=None, images_per_style=4, file_format='png'):
        """Generate up to images_per_style images for each style in styles."""
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
            console.print(f"\n[bold cyan]Generating {images_per_style} image{'s' if images_per_style != 1 else ''} for: {styled_prompt}[/bold cyan]")

            try:
                self.test_cookie()
                url_encoded_prompt = quote(styled_prompt)
                payload = f"q={url_encoded_prompt}&qs=ds"

                preload_response = self.session.get(f"{BING_URL}/images/create", timeout=30)
                if preload_response.status_code == 200:
                    self.session.cookies.update(preload_response.cookies)
                    self.log("Preloaded page, captured cookies", "info")

                image_links = None
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
                        image_links = self._poll_images(polling_url, images_per_style)
                        break

                if not image_links:
                    image_links = self._fallback_get_images(url_encoded_prompt)

                saved_files = self._save_images(image_links, images_per_style, style, file_format)
                all_saved_files.extend(saved_files)
                self.log(f"Saved {len(saved_files)} images for style '{style or 'none'}'", "info")

            except Exception as e:
                self.log(f"Error for '{styled_prompt}': {str(e)}", "error")
                console.print(f"[red]Error for style '{style or 'none'}': {str(e)}[/red]")

            time.sleep(2)

        return all_saved_files

    def _save_images(self, links, download_count, style=None, file_format='png'):
        """Save images to the output directory with progress."""
        num_to_download = min(download_count, len(links))
        console.print(f"\n[bold magenta]Downloading {num_to_download} image{'s' if num_to_download != 1 else ''} to {self.output_dir} ({style or 'no style'})[/bold magenta]")
        
        saved_files = []
        with Progress() as progress:
            download_task = progress.add_task("[cyan]Downloading...", total=num_to_download)
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
                progress.update(download_task, advance=1)

        if not saved_files:
            self.log(f"No images saved for style '{style or 'none'}'", "warning")
        return saved_files

    def create_thumbnail(self, image_path, thumbnail_path, size=(128, 128), output_format='png'):
        """Generate a thumbnail for the given image."""
        try:
            with Image.open(image_path) as img:
                img.thumbnail(size, Image.Resampling.LANCZOS)
                img.save(thumbnail_path, format=output_format.upper())
        except Image.UnidentifiedImageError:
            raise ValueError("Invalid or corrupted image file")
        except PermissionError:
            raise PermissionError(f"No write permission for {thumbnail_path}")

# --- Helper Functions for Menu ---
def display_menu(selected_styles, images_per_style):
    """Display the main interactive menu with current styles and images per style."""
    table = Table(title="[bold cyan]Pixel's DALL-E Image Generator Menu[/bold cyan]", show_header=False, expand=False)
    table.add_column("Option", style="cyan")
    table.add_column("Description", style="white")
    table.add_row("1", "Generate images with a new prompt")
    table.add_row("2", "Generate images from a prompt file")
    table.add_row("3", "Select styles for generation")
    table.add_row("4", "View or modify settings")
    table.add_row("5", "Exit program")
    table.add_row("6", "Generate thumbnails for saved images")
    table.add_row("7", "List generated images")
    table.add_row("8", "Clear output directory")
    table.add_row("9", "Preview images in output directory")
    table.add_row("10", "View help and usage information")
    console.print(Panel(table, expand=False))
    console.print(f"[yellow]Current styles: {', '.join(selected_styles) if selected_styles else 'None'} ({images_per_style} image{'s' if images_per_style != 1 else ''} per style)[/yellow]")
    return Prompt.ask("[bold green]Select an option (1-10)[/bold green]", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"], default="1")

def display_help():
    """Display a detailed help menu with usage information."""
    help_text = (
        "[bold cyan]Pixel's DALL-E Image Generator CLI - Help Menu[/bold cyan]\n\n"
        "[bold]Overview[/bold]\n"
        "This tool generates AI images using Bing's DALL-E integration. It supports interactive mode for generating images with various styles, managing output, and configuring settings. You can also use command-line arguments for quick execution.\n\n"
        "[bold]Menu Options[/bold]\n"
        "- [cyan]1. Generate images with a new prompt[/cyan]: Enter a single prompt (e.g., 'a sunset over mountains') and generate images with selected styles.\n"
        "- [cyan]2. Generate images from a prompt file[/cyan]: Provide a text file with one prompt per line (e.g., 'prompts.txt') to batch-generate images.\n"
        "- [cyan]3. Select styles for generation[/cyan]: Choose from 30+ styles (e.g., watercolor, cyberpunk, anime) or use 'all' for all styles.\n"
        "- [cyan]4. View or modify settings[/cyan]: View or change output directory, images per style, log level, cookie, or custom styles.\n"
        "- [cyan]5. Exit program[/cyan]: Exit the interactive mode.\n"
        "- [cyan]6. Generate thumbnails for saved images[/cyan]: Create thumbnails (custom size/format) for selected images, saved in a 'thumbnails' subfolder.\n"
        "- [cyan]7. List generated images[/cyan]: Display a table of saved images with filenames, styles, and creation times.\n"
        "- [cyan]8. Clear output directory[/cyan]: Delete all images in the output directory after confirmation.\n"
        "- [cyan]9. Preview images in output directory[/cyan]: Open selected images in your default image viewer.\n"
        "- [cyan]10. View help and usage information[/cyan]: Show this help menu.\n\n"
        "[bold]Command-Line Arguments[/bold]\n"
        "- [cyan]prompt[/cyan]: A single prompt or path to a prompt file.\n"
        "- [cyan]--output, -o[/cyan]: Output directory (default: ./PixelImages).\n"
        "- [cyan]--count, -c[/cyan]: Images per style (1-4, default: 4).\n"
        "- [cyan]--cookie, -k[/cyan]: Authentication cookie (overrides config).\n"
        "- [cyan]--log-level[/cyan]: Logging level (DEBUG, INFO, WARNING, ERROR; default: INFO).\n"
        "- [cyan]--styles, -s[/cyan]: Comma-separated styles (e.g., 'watercolor,anime').\n"
        "- [cyan]--format, -f[/cyan]: Image format (png, jpg, jpeg; default: png).\n"
        "- [cyan]--verbose[/cyan]: Enable verbose output.\n\n"
        "[bold]Examples[/bold]\n"
        "- Interactive mode: [cyan]python pixel_dalle_gen.py[/cyan]\n"
        "- Single prompt: [cyan]python pixel_dalle_gen.py 'a dragon in ukiyo-e style' -o ./images -c 3[/cyan]\n"
        "- Prompt file: [cyan]python pixel_dalle_gen.py prompts.txt -o ./images --log-level DEBUG[/cyan]\n"
        "- Specific styles: [cyan]python pixel_dalle_gen.py 'a cityscape' --styles 'cyberpunk,holographic'[/cyan]\n\n"
        "[bold]Notes[/bold]\n"
        "- Create a prompt file (e.g., 'prompts.txt') with one prompt per line.\n"
        "- Custom styles can be added via the config file (pixel_dalle_config.ini) or settings menu.\n"
        "- Images are saved in the output directory with filenames like 'pixel_image_style_timestamp_index.png'.\n"
        "- For command-line help, use: [cyan]python pixel_dalle_gen.py --help[/cyan]."
    )
    console.print(Panel(help_text, expand=False))
    Prompt.ask("[bold green]Press Enter to return to the main menu[/bold green]")

def select_styles(current_styles, images_per_style):
    """Display and allow selection of styles."""
    console.print("\n[bold cyan]Available Styles[/bold cyan]")
    console.print(f"[yellow]Note: {images_per_style} image{'s' if images_per_style != 1 else ''} will be generated for each selected style.[/yellow]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Number", style="cyan", width=8)
    table.add_column("Style", style="white")
    table.add_column("Description", style="white")
    
    style_descriptions = {
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
    
    for i, style in enumerate(ALL_STYLES, 1):
        table.add_row(str(i), style, style_descriptions.get(style, "Custom style"))
    console.print(table)

    console.print("[yellow]Enter style numbers (e.g., '1,3,5'), 'all', or press Enter for none[/yellow]")
    style_input = Prompt.ask("Styles").strip().lower()
    if style_input == "all":
        if Confirm.ask(f"[bold yellow]Generate {images_per_style} image{'s' if images_per_style != 1 else ''} for all {len(ALL_STYLES)} styles ({len(ALL_STYLES) * images_per_style} images)?[/bold yellow]", default=False):
            return ALL_STYLES
        return []
    elif style_input:
        try:
            indices = [int(i) - 1 for i in style_input.split(",") if i.strip().isdigit()]
            selected = [ALL_STYLES[i] for i in indices if 0 <= i < len(ALL_STYLES)]
            if not selected:
                console.print("[red]No valid styles selected. Using none.[/red]")
                return []
            if len(selected) * images_per_style > 12 and not Confirm.ask(f"[bold yellow]Generate {len(selected) * images_per_style} images for {len(selected)} styles?[/bold yellow]", default=False):
                return []
            return selected
        except ValueError:
            console.print("[red]Invalid input. Using none.[/red]")
            return []
    return []

def display_settings(config, args):
    """Display current settings."""
    table = Table(title="[bold cyan]Current Settings[/bold cyan]", show_header=True, header_style="bold magenta")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Output Directory", config["output_dir"])
    table.add_row("Images per Style", str(args.count))
    table.add_row("Log Level", args.log_level)
    table.add_row("Authentication Cookie", "Present" if config["cookie"] else "Not Set")
    table.add_row("Custom Styles", config["custom_styles"] or "None")
    console.print(table)

def modify_settings(config, args):
    """Allow modification of settings."""
    console.print("\n[bold cyan]Modify Settings[/bold cyan]")
    if Confirm.ask("Change output directory?", default=False):
        new_dir = Prompt.ask("New output directory", default=config["output_dir"]).strip()
        config["output_dir"] = new_dir if new_dir else config["output_dir"]
    if Confirm.ask("Change images per style?", default=False):
        args.count = IntPrompt.ask("Images per style (1-4)", default=args.count, choices=["1", "2", "3", "4"])
    if Confirm.ask("Change log level?", default=False):
        args.log_level = Prompt.ask("Log level", default=args.log_level, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    if Confirm.ask("Change authentication cookie?", default=False):
        new_cookie = Prompt.ask("Enter new authentication cookie", default=config["cookie"]).strip()
        config["cookie"] = new_cookie if new_cookie else config["cookie"]
    if Confirm.ask("Change custom styles?", default=False):
        new_styles = Prompt.ask("Enter custom styles (comma-separated)", default=config["custom_styles"]).strip()
        config["custom_styles"] = new_styles if new_styles else config["custom_styles"]
    return config, args

# --- Main Execution ---
def main():
    # Display banner
    console.print(f"[bold cyan]Pixel's DALL-E Image Generator CLI v2.0.1 by PrimalCore[/bold cyan]")
    console.print("[cyan]A professional CLI tool for generating AI images with interactive style variations.[/cyan]")
    console.print("[cyan]Select 'Help' (option 10) in the menu for detailed usage guidance.[/cyan]\n")

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Generate AI images with Pixel's DALL-E Image Generator CLI and interactive style variations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python pixel_dalle_gen.py 'a beautiful sunset' -o ./images -c 3\n"
               "  python pixel_dalle_gen.py prompts.txt -o ./images --log-level DEBUG\n"
               "  python pixel_dalle_gen.py --cookie '_U=YOUR_COOKIE' -o ./images\n"
               "  python pixel_dalle_gen.py 'a cat' --styles 'watercolor,cyberpunk,ukiyo-e'"
    )
    parser.add_argument("prompt", nargs="?", help="Image description prompt or file path with prompts")
    parser.add_argument("--output", "-o", default=os.path.abspath("./PixelImages"), help="Output directory (default: ./PixelImages)")
    parser.add_argument("--count", "-c", type=int, default=4, help="Images per style (1-4, default: 4)")
    parser.add_argument("--cookie", "-k", help="Authentication cookie (overrides default and config)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level (default: INFO)")
    parser.add_argument(
        "--styles", "-s",
        help="Comma-separated list of styles to apply to the prompt (e.g., 'watercolor,cyberpunk,ukiyo-e')"
    )
    parser.add_argument(
        "--format", "-f", default="png", choices=["png", "jpg", "jpeg"],
        help="Output image file format (default: png)"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(args.log_level)

    if args.verbose:
        console.print("[yellow]Verbose output mode enabled.[/yellow]")

    try:
        # Load or set configuration
        config, custom_styles = load_config()
        auth_cookie = args.cookie or config["cookie"]
        output_dir = args.output or config["output_dir"]
        ALL_STYLES.extend([s for s in custom_styles if s not in ALL_STYLES])

        # Validate count
        if args.count and (args.count < 1 or args.count > 4):
            raise ValueError("Images per style must be between 1 and 4.")

        generator = PixelDalleGenerator(auth_cookie, output_dir, logger)

        # Parse styles if provided
        styles = []
        if args.styles:
            styles = [s.strip() for s in args.styles.split(",") if s.strip()]

        # Process command-line prompt or file if provided
        if args.prompt:
            if os.path.isfile(args.prompt):
                prompts = read_prompts_file(args.prompt)
                logger.info(f"Processing {len(prompts)} prompts from {args.prompt}")
                for i, prompt in enumerate(prompts, 1):
                    console.print(f"\n[bold]Processing prompt {i}/{len(prompts)}:[/bold] {prompt}")
                    try:
                        total_images = len(styles or [None]) * min(args.count or 4, 4)
                        if total_images > 12 and not Confirm.ask(f"[bold yellow]Generate {total_images} images for this prompt?[/bold yellow]", default=False):
                            continue
                        saved_files = generator.generate_images(prompt, styles=styles, images_per_style=min(args.count or 4, 4), file_format=args.format)
                        logger.info(f"Successfully saved {len(saved_files)} images for '{prompt}'")
                        with open(os.path.join(output_dir, "generation_log.txt"), "a") as log:
                            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Success: {prompt} - {len(saved_files)} images\n")
                    except Exception as e:
                        logger.error(f"Error for '{prompt}': {str(e)}")
                        console.print(f"[red]Error: {str(e)}[/red]")
                        with open(os.path.join(output_dir, "generation_log.txt"), "a") as log:
                            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Error: {prompt} - {str(e)}\n")
                    time.sleep(2)
            else:
                console.print(f"\n[bold]Processing prompt:[/bold] {args.prompt}")
                try:
                    total_images = len(styles or [None]) * min(args.count or 4, 4)
                    if total_images > 12 and not Confirm.ask(f"[bold yellow]Generate {total_images} images for this prompt?[/bold yellow]", default=False):
                        return
                    saved_files = generator.generate_images(args.prompt, styles=styles, images_per_style=min(args.count or 4, 4), file_format=args.format)
                    logger.info(f"Successfully saved {len(saved_files)} images for '{args.prompt}'")
                    with open(os.path.join(output_dir, "generation_log.txt"), "a") as log:
                        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Success: {args.prompt} - {len(saved_files)} images\n")
                except Exception as e:
                    logger.error(f"Error for '{args.prompt}': {str(e)}")
                    console.print(f"[red]Error: {str(e)}[/red]")
                    with open(os.path.join(output_dir, "generation_log.txt"), "a") as log:
                        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Error: {args.prompt} - {str(e)}\n")

        # Interactive menu loop
        console.print("\n[bold green]Starting interactive mode.[/bold green]")
        selected_styles = styles
        while True:
            choice = display_menu(selected_styles, args.count)
            if choice == "1":
                console.print(f"\n[bold yellow]Current styles: {', '.join(selected_styles) if selected_styles else 'None'} ({args.count} image{'s' if args.count != 1 else ''} per style)[/bold yellow]")
                if selected_styles and Confirm.ask("Use current styles?", default=True):
                    curr_styles = selected_styles
                else:
                    curr_styles = select_styles(selected_styles, args.count)
                    if curr_styles:
                        selected_styles = curr_styles
                prompt = Prompt.ask("[bold green]Enter a prompt[/bold green]").strip()
                if not prompt:
                    console.print("[red]Prompt cannot be empty.[/red]")
                    continue
                total_images = len(curr_styles or [None]) * args.count
                if total_images > 12 and not Confirm.ask(f"[bold yellow]Generate {total_images} images for this prompt?[/bold yellow]", default=False):
                    continue
                try:
                    saved_files = generator.generate_images(prompt, styles=curr_styles, images_per_style=args.count, file_format=args.format)
                    console.print(f"[bold green]Saved {len(saved_files)} images for '{prompt}'.[/bold green]")
                    logger.info(f"Successfully saved {len(saved_files)} images for '{prompt}'")
                    with open(os.path.join(output_dir, "generation_log.txt"), "a") as log:
                        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Success: {prompt} - {len(saved_files)} images\n")
                except Exception as e:
                    console.print(f"[red]Error: {str(e)}[/red]")
                    logger.error(f"Error for '{prompt}': {str(e)}")
                    with open(os.path.join(output_dir, "generation_log.txt"), "a") as log:
                        log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Error: {prompt} - {str(e)}\n")

            elif choice == "2":
                console.print(f"\n[bold yellow]Current styles: {', '.join(selected_styles) if selected_styles else 'None'} ({args.count} image{'s' if args.count != 1 else ''} per style)[/bold yellow]")
                if selected_styles and Confirm.ask("Use current styles?", default=True):
                    curr_styles = selected_styles
                else:
                    curr_styles = select_styles(selected_styles, args.count)
                    if curr_styles:
                        selected_styles = curr_styles
                file_path = Prompt.ask("[bold green]Enter prompt file path[/bold green]").strip()
                if not os.path.isfile(file_path):
                    console.print("[red]File not found.[/red]")
                    continue
                prompts = read_prompts_file(file_path)
                total_images = len(curr_styles or [None]) * args.count * len(prompts)
                if total_images > 12 and not Confirm.ask(f"[bold yellow]Generate {total_images} images for {len(prompts)} prompts?[/bold yellow]", default=False):
                    continue
                for i, prompt in enumerate(prompts, 1):
                    console.print(f"\n[bold]Processing prompt {i}/{len(prompts)}:[/bold] {prompt}")
                    try:
                        saved_files = generator.generate_images(prompt, styles=curr_styles, images_per_style=args.count, file_format=args.format)
                        logger.info(f"Successfully saved {len(saved_files)} images for '{prompt}'")
                        with open(os.path.join(output_dir, "generation_log.txt"), "a") as log:
                            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Success: {prompt} - {len(saved_files)} images\n")
                    except Exception as e:
                        console.print(f"[red]Error: {str(e)}[/red]")
                        logger.error(f"Error for '{prompt}': {str(e)}")
                        with open(os.path.join(output_dir, "generation_log.txt"), "a") as log:
                            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Error: {prompt} - {str(e)}\n")
                    time.sleep(2)

            elif choice == "3":
                selected_styles = select_styles(selected_styles, args.count)
                console.print(f"[green]Selected styles: {', '.join(selected_styles) if selected_styles else 'None'}[/green]")

            elif choice == "4":
                display_settings(config, args)
                config, args = modify_settings(config, args)
                output_dir = config["output_dir"]
                custom_styles = config["custom_styles"].split(",") if config["custom_styles"] else []
                custom_styles = [s.strip() for s in custom_styles if s.strip()]
                ALL_STYLES.extend([s for s in custom_styles if s not in ALL_STYLES])
                logger = setup_logging(args.log_level)
                generator = PixelDalleGenerator(auth_cookie, output_dir, logger)

            elif choice == "5":
                if Confirm.ask("[bold yellow]Are you sure you want to exit?[/bold yellow]", default=False):
                    console.print("[bold green]Exiting program.[/bold green]")
                    break

            elif choice == "6":
                try:
                    generate_thumbnails(config, generator)
                    logger.info("Thumbnail generation completed")
                except Exception as e:
                    console.print(f"[red]Error generating thumbnails: {str(e)}[/red]")
                    logger.error(f"Error generating thumbnails: {str(e)}")

            elif choice == "7":
                try:
                    list_generated_images(output_dir)
                    logger.info("Listed generated images")
                except Exception as e:
                    console.print(f"[red]Error listing images: {str(e)}[/red]")
                    logger.error(f"Error listing images: {str(e)}")

            elif choice == "8":
                try:
                    clear_output_directory(output_dir, logger)
                    logger.info("Cleared output directory")
                except Exception as e:
                    console.print(f"[red]Error clearing output directory: {str(e)}[/red]")
                    logger.error(f"Error clearing output directory: {str(e)}")

            elif choice == "9":
                try:
                    preview_images(output_dir)
                    logger.info("Previewed images")
                except Exception as e:
                    console.print(f"[red]Error previewing images: {str(e)}[/red]")
                    logger.error(f"Error previewing images: {str(e)}")

            elif choice == "10":
                display_help()

        # Save updated config
        save_config(auth_cookie, output_dir, custom_styles)

    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        console.print(f"[red]Fatal error: {str(e)}[/red]")

if __name__ == "__main__":
    main()
