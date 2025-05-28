#!/usr/bin/env python3
# =====================================
# Script:     Pixel's DALL-E Image Generator CLI
# Author:     Primal Core
# Version:    1.9.6
# Description: A professional CLI tool to fetch AI-generated images with interactive style variations.
# License:    MIT
# Dependencies: requests, rich
# Usage:      Run it 
=====================================

import os
import random
import re
import time
import logging
import argparse
from urllib.parse import quote
from http.cookies import SimpleCookie
import requests
try:
    from rich.console import Console
    from rich.logging import RichHandler
    from rich.progress import track
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt, Confirm
    console = Console()
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

DEFAULT_AUTH_COOKIE = "_U=YOUR_COOKIE_QUICK_SLOT"

SENSITIVE_WORDS = {"porn", "sex", "naked", "kill", "drug", "gore"}

ERROR_TIMEOUT = "Request timed out after 10 minutes."
ERROR_REDIRECT = "Failed to follow redirect. Please check cookie or network."
ERROR_BLOCKED_PROMPT = "Prompt blocked due to sensitive content."
ERROR_NO_IMAGES = "No images found in response."

# --- Popular Styles List for "all" Option ---
ALL_STYLES = [
    "watercolor", "oil painting", "cyberpunk", "steampunk", "cartoon", "anime",
    "photorealistic", "pixel art", "low poly", "noir", "futuristic", "retro",
    "fantasy", "impressionist", "Van Gogh", "Picasso", "minimalist", "surreal",
    "vaporwave", "gothic", "pop art", "comic book", "sketch", "chibi"
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
    config = {"cookie": DEFAULT_AUTH_COOKIE, "output_dir": "/storage/emulated/0/PixelImages"}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                if "=" in line and not line.strip().startswith("#"):
                    key, value = [x.strip() for x in line.split("=", 1)]
                    config[key] = value
    return config

def save_config(cookie, output_dir):
    """Save settings to config file."""
    with open(CONFIG_FILE, "w") as f:
        f.write(f"cookie={cookie}\n")
        f.write(f"output_dir={output_dir}\n")

def create_directory(output_dir):
    """Create the output directory if it doesn't exist."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        console.print(f"[green]Created directory: {output_dir}[/green]")
    if not os.access(output_dir, os.W_OK):
        raise PermissionError(f"Output directory '{output_dir}' is not writable.")

def generate_filename(output_dir, index, style=None):
    """Generate a unique filename for an image, including style if provided."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    style_part = f"_{style.replace(' ', '_')}" if style else ""
    return os.path.join(output_dir, f"pixel_image{style_part}_{timestamp}_{index}.png")

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
            response = self.session.get(
                f"{BING_URL}/images/create?q={url_encoded_prompt}&FORM=GENCRE", timeout=600
            )
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
                    return self._poll_images(polling_url, images_per_style=4)  # Default for fallback

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
                    return self._poll_images(polling_url, images_per_style=4)  # Default for fallback

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

    def generate_images(self, prompt, styles=None, images_per_style=4):
        """Generate up to images_per_style images for each style in styles."""
        if not prompt:
            raise ValueError("Prompt cannot be empty.")
        if images_per_style > 4:
            raise ValueError("Images per style cannot exceed 4.")

        blocked, word = contains_sensitive_words(prompt)
        if blocked:
            raise BlockedPromptError(f"Blocked due to: {word}")

        styles = styles or [None]  # Default to no style if none provided
        all_saved_files = []

        for style in styles:
            styled_prompt = f"{prompt}, {style}" if style else prompt
            console.print(f"\n[bold cyan]Generating {images_per_style} image{'s' if images_per_style != 1 else ''} for: {styled_prompt}[/bold cyan]")

            try:
                self.test_cookie()
                url_encoded_prompt = quote(styled_prompt)
                payload = f"q={url_encoded_prompt}&qs=ds"

                # Preload to capture cookies
                preload_response = self.session.get(f"{BING_URL}/images/create", timeout=30)
                if preload_response.status_code == 200:
                    self.session.cookies.update(preload_response.cookies)
                    self.log("Preloaded page, captured cookies", "info")

                # Try POST with different rt parameters
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

                # Fallback to GET if POST fails
                if not image_links:
                    image_links = self._fallback_get_images(url_encoded_prompt)

                # Save images for this style
                saved_files = self._save_images(image_links, images_per_style, style)
                all_saved_files.extend(saved_files)
                self.log(f"Saved {len(saved_files)} images for style '{style or 'none'}'", "info")

            except Exception as e:
                self.log(f"Error for '{styled_prompt}': {str(e)}", "error")
                console.print(f"[red]Error for style '{style or 'none'}': {str(e)}[/red]")

            time.sleep(2)  # Brief pause between styles to avoid rate limiting

        return all_saved_files

    def _save_images(self, links, download_count, style=None):
        """Save images to the output directory with progress."""
        num_to_download = min(download_count, len(links))
        console.print(f"\n[bold magenta]Downloading {num_to_download} image{'s' if num_to_download != 1 else ''} to {self.output_dir} ({style or 'no style'})[/bold magenta]")
        saved_files = []
        for i in track(range(num_to_download), description=f"Downloading ({style or 'no style'})..."):
            try:
                link = links[i]
                response = self.session.get(link, timeout=30)
                if response.status_code == 200:
                    filename = generate_filename(self.output_dir, i, style)
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
    console.print(Panel(table, expand=False))
    console.print(f"[yellow]Current styles: {', '.join(selected_styles) if selected_styles else 'None'} ({images_per_style} image{'s' if images_per_style != 1 else ''} per style)[/yellow]")
    return Prompt.ask("[bold green]Select an option (1-5)[/bold green]", choices=["1", "2", "3", "4", "5"], default="1")

def select_styles(current_styles, images_per_style):
    """Display and allow selection of styles."""
    console.print("\n[bold cyan]Available Styles[/bold cyan]")
    console.print(f"[yellow]Note: {images_per_style} image{'s' if images_per_style != 1 else ''} will be generated for each selected style.[/yellow]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Number", style="cyan", width=8)
    table.add_column("Style", style="white")
    for i, style in enumerate(ALL_STYLES, 1):
        table.add_row(str(i), style)
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
    return config, args

# --- Main Execution ---
def main():
    # Display banner
    console.print(f"[bold cyan]Pixel's DALL-E Image Generator CLI v1.5.3 by PrimalCore[/bold cyan]")
    console.print("[cyan]A professional CLI tool for generating AI images with interactive style variations.[/cyan]")
    console.print("[cyan]Run with --help for usage details.[/cyan]\n")

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Generate AI images with Pixel's DALL-E Image Generator CLI and interactive style variations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python pixel_dalle_gen.py 'a beautiful sunset' -o ./images -c 3\n"
               "  python pixel_dalle_gen.py prompts.txt -o ./images --log-level DEBUG\n"
               "  python pixel_dalle_gen.py --cookie '_U=YOUR_COOKIE' -o ./images\n"
               "  python pixel_dalle_gen.py 'a cat' --styles 'watercolor,cyberpunk,Van Gogh'"
    )
    parser.add_argument("prompt", nargs="?", help="Image description prompt or file path with prompts")
    parser.add_argument("--output", "-o", default="/storage/emulated/0/PixelImages", help="Output directory (default: /storage/emulated/0/PixelImages)")
    parser.add_argument("--count", "-c", type=int, default=4, help="Images per style (1-4, default: 4)")
    parser.add_argument("--cookie", "-k", help="Authentication cookie (overrides default and config)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="Logging level (default: INFO)")
    parser.add_argument(
        "--styles", "-s",
        help="Comma-separated list of styles to apply to the prompt (e.g., 'watercolor,cyberpunk,Van Gogh')"
    )
    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(args.log_level)

    try:
        # Load or set configuration
        config = load_config()
        auth_cookie = args.cookie or config["cookie"]
        output_dir = args.output or config["output_dir"]

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
                        saved_files = generator.generate_images(prompt, styles=styles, images_per_style=min(args.count or 4, 4))
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
                    saved_files = generator.generate_images(args.prompt, styles=styles, images_per_style=min(args.count or 4, 4))
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
        selected_styles = styles  # Initialize with command-line styles, if any
        while True:
            choice = display_menu(selected_styles, args.count)
            if choice == "1":
                console.print(f"\n[bold yellow]Current styles: {', '.join(selected_styles) if selected_styles else 'None'} ({args.count} image{'s' if args.count != 1 else ''} per style)[/bold yellow]")
                if selected_styles and Confirm.ask("Use current styles?", default=True):
                    curr_styles = selected_styles
                else:
                    curr_styles = select_styles(selected_styles, args.count)
                    if curr_styles:
                        selected_styles = curr_styles  # Update global styles
                prompt = Prompt.ask("[bold green]Enter a prompt[/bold green]").strip()
                if not prompt:
                    console.print("[red]Prompt cannot be empty.[/red]")
                    continue
                total_images = len(curr_styles or [None]) * args.count
                if total_images > 12 and not Confirm.ask(f"[bold yellow]Generate {total_images} images for this prompt?[/bold yellow]", default=False):
                    continue
                try:
                    saved_files = generator.generate_images(prompt, styles=curr_styles, images_per_style=args.count)
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
                        selected_styles = curr_styles  # Update global styles
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
                        saved_files = generator.generate_images(prompt, styles=curr_styles, images_per_style=args.count)
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
                logger = setup_logging(args.log_level)
                generator = PixelDalleGenerator(auth_cookie, output_dir, logger)

            elif choice == "5":
                if Confirm.ask("[bold yellow]Are you sure you want to exit?[/bold yellow]", default=False):
                    console.print("[bold green]Exiting program.[/bold green]")
                    break

        # Save updated config
        save_config(auth_cookie, output_dir)

    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        console.print(f"[red]Fatal error: {str(e)}[/red]")

if __name__ == "__main__":
    main()
