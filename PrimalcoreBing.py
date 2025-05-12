#!/usr/bin/env python3
# =====================================
# Script:     Bing Image Generator
# Author:     Primal Core
# Version:    1.9
# Description: Fetches AI-generated images from Bing using a prompt and saves them to a specified directory.
# License:    MIT
# Dependencies: requests, rich
# =====================================

import argparse
import os
import random
import re
import time
import logging
from http.cookies import SimpleCookie
import requests
from urllib.parse import quote
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel

# --- Configuration ---

# Initialize rich console
console = Console()

# Default Bing URL
BING_URL = os.getenv("BING_URL", "https://www.bing.com")

# Generate a random forwarded IP
FORWARDED_IP = f"13.{random.randint(104, 107)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Default HTTP headers
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

# Hardcoded auth cookie (Your _U cookie value for personal use)
DEFAULT_AUTH_COOKIE = "_U=ADD_YOUR_COOKIE_HERE"

# Sensitive words for prompt filtering
SENSITIVE_WORDS = {
    # Adult content
    "porn", "pornographic", "xxx", "sex", "naked", "boobs", "breasts", "penis", "vagina",
    # Hate speech
    "racist", "nigger", "faggot", "bitch", "slut", "whore",
    # Violence and harm
    "kill", "murder", "suicide", "abuse", "terrorist", "terrorism", "bomb", "shooting",
    # Illegal activities
    "drug", "drugs", "cocaine", "heroin", "hack", "hacking", "piracy", "crime",
    # Graphic content
    "gore", "blood", "mutilation", "torture", "corpse", "decapitation",
    # Malware and phishing
    "phishing", "malware", "virus", "ransomware", "trojan",
}

# Error messages
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
    """Parse a cookie string into a dictionary.

    Args:
        cookie_string (str): The cookie string to parse.

    Returns:
        dict: Dictionary of cookie key-value pairs.
    """
    cookie = SimpleCookie()
    cookie.load(cookie_string)
    return {key: morsel.value for key, morsel in cookie.items()}

def contains_sensitive_words(prompt, sensitive_words):
    """Check if the prompt contains sensitive words.

    Args:
        prompt (str): The prompt to check.
        sensitive_words (set): Set of sensitive words.

    Returns:
        tuple: (bool, str or None) indicating if a sensitive word was found and the word itself.
    """
    prompt_lower = prompt.lower()
    for word in sensitive_words:
        pattern = fr"\b{re.escape(word)}\b"
        if re.search(pattern, prompt_lower):
            return True, word
    return False, None

def url_encode_prompt(prompt):
    """URL-encode the prompt for safe use in requests.

    Args:
        prompt (str): The prompt to encode.

    Returns:
        str: URL-encoded prompt.
    """
    return quote(prompt)

def create_directory(output_dir):
    """Create the output directory if it doesn't exist.

    Args:
        output_dir (str): The directory path to create.

    Raises:
        PermissionError: If the directory is not writable.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        console.print(f"[bold green]Created directory:[/bold green] {output_dir}")
    if not os.access(output_dir, os.W_OK):
        raise PermissionError(f"Output directory '{output_dir}' is not writable.")

def generate_filename(output_dir, index):
    """Generate a unique filename for an image.

    Args:
        output_dir (str): The directory to save the image.
        index (int): The image index.

    Returns:
        str: The full path to the image file.
    """
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(output_dir, f"bing_image_{timestamp}_{index}.png")

def get_output_dir(default_dir, quiet=False):
    """Prompt user to choose default or custom output directory.

    Args:
        default_dir (str): The default output directory.
        quiet (bool): Suppress prompts if True.

    Returns:
        str: The chosen output directory.
    """
    if quiet:
        return default_dir
    console.print(Panel("[bold cyan]Save Directory[/bold cyan]", expand=False))
    console.print(f"[bold]Default directory:[/bold] {default_dir}")
    choice = console.input("[bold yellow]Use default directory? (y/n): [/bold yellow]").strip().lower()
    if choice in ('', 'y', 'yes'):
        return default_dir
    custom_dir = console.input("[bold yellow]Enter custom directory (e.g., /sdcard/Pictures/MyImages): [/bold yellow]").strip()
    if not custom_dir:
        console.print("[bold yellow]⚠️ No directory provided, using default.[/bold yellow]")
        return default_dir
    custom_dir = os.path.abspath(custom_dir)
    if not custom_dir.startswith(('/storage/emulated/0', '/sdcard')) and os.name != "nt":
        console.print("[bold yellow]⚠️ Invalid directory. Must be in Internal Storage. Using default.[/bold yellow]")
        return default_dir
    return custom_dir

# --- Core Image Generator Class ---

class BingImageGenerator:
    """A class to generate and save images from Bing's AI image creator.

    Attributes:
        auth_cookie (str): Authentication cookie for Bing.
        output_dir (str): Directory to save generated images.
        quiet (bool): Suppress logging if True.
        session (requests.Session): HTTP session for requests.
        logger (logging.Logger): Logger for the class.
    """

    def __init__(self, auth_cookie=None, output_dir="BingImages", quiet=False):
        """Initialize the Bing Image Generator.

        Args:
            auth_cookie (str, optional): Authentication cookie for Bing. Defaults to None.
            output_dir (str): Directory to save images.
            quiet (bool): Suppress logging if True.

        Raises:
            InvalidCookieError: If no valid cookie is provided.
        """
        self.auth_cookie = auth_cookie or os.getenv("BING_AUTH_COOKIE") or DEFAULT_AUTH_COOKIE
        self.output_dir = os.path.abspath(output_dir)
        self.quiet = quiet
        self.logger = setup_logging(quiet)
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        if not self.auth_cookie:
            raise InvalidCookieError("No authentication cookie provided. Use -U or set BING_AUTH_COOKIE environment variable.")
        self.session.cookies.update(parse_cookie_string(self.auth_cookie))
        create_directory(self.output_dir)

    def test_cookie(self):
        """Test if the authentication cookie is valid.

        Returns:
            bool: True if the cookie is valid.

        Raises:
            InvalidCookieError: If the cookie is invalid or access is denied.
            NetworkError: If a network error occurs.
        """
        console.print("[bold blue]Verifying authentication cookie...[/bold blue]")
        try:
            response = self.session.get(f"{BING_URL}/images/create", timeout=30)
            if response.status_code == 200 and "create" in response.url and "form" in response.text.lower():
                self.session.cookies.update(response.cookies)
                console.print("[bold green]✓ Cookie is valid![/bold green]")
                return True
            raise InvalidCookieError(f"Invalid cookie or access denied: Status {response.status_code}")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Cookie test failed: {str(e)}")

    def _try_post_request(self, url, payload):
        """Attempt a POST request and return response if successful.

        Args:
            url (str): The URL to send the POST request to.
            payload (str): The data to send in the POST request.

        Returns:
            requests.Response: The response if successful, else None.

        Raises:
            BlockedPromptError: If the prompt is blocked by Bing.
            NetworkError: If a network error occurs.
        """
        try:
            response = self.session.post(url, allow_redirects=False, data=payload, timeout=600)
            if "this prompt has been blocked" in response.text.lower():
                raise BlockedPromptError(ERROR_BLOCKED_PROMPT)
            return response if response.status_code == 302 else None
        except requests.exceptions.RequestException as e:
            console.print(f"[bold yellow]⚠️ POST request failed: {str(e)}[/bold yellow]")
            raise NetworkError(f"POST request failed: {str(e)}")

    def _fallback_get_images(self, url_encoded_prompt):
        """Fallback to GET request and parse HTML for images or redirects.

        Args:
            url_encoded_prompt (str): URL-encoded prompt.

        Returns:
            list: List of image URLs.

        Raises:
            NetworkError: If a network error occurs.
            NoImagesError: If no images or redirects are found.
        """
        console.print("[bold blue]Falling back to GET request...[/bold blue]")
        try:
            response = self.session.get(
                f"{BING_URL}/images/create?q={url_encoded_prompt}&FORM=GENCRE", timeout=600
            )
            console.print(f"[bold blue]GET response: Status {response.status_code}[/bold blue]")

            # Look for image links
            image_links = re.findall(r'src="([^"]+)"', response.text)
            normal_image_links = [
                link.split("?w=")[0] for link in image_links if "?w=" in link and link.startswith("https")
            ]
            normal_image_links = list(set(normal_image_links))
            if normal_image_links:
                console.print("[bold green]Found images in HTML fallback[/bold green]")
                return normal_image_links

            # Look for redirect URLs
            redirect_urls = re.findall(r'location\.href\s*=\s*"([^"]+)"', response.text)
            if redirect_urls:
                redirect_url = redirect_urls[0]
                request_id = redirect_url.split("id=")[-1] if "id=" in redirect_url else None
                if request_id:
                    self.session.get(f"{BING_URL}{redirect_url}")
                    polling_url = f"{BING_URL}/images/create/async/results/{request_id}?q={url_encoded_prompt}"
                    return self._poll_images(polling_url)

            # Try form action
            form_actions = re.findall(r'<form[^>]+action="([^"]+)"', response.text)
            if form_actions:
                console.print("[bold blue]Trying form action endpoint[/bold blue]")
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
        """Poll the async results URL for image links.

        Args:
            polling_url (str): URL to poll for results.

        Returns:
            list: List of image URLs.

        Raises:
            TimeoutError: If polling exceeds the timeout duration.
            NoImagesError: If no images are found.
            NetworkError: If a network error occurs.
        """
        console.print("[bold blue]Waiting for Bing to generate images...[/bold blue]")
        start_wait = time.time()
        total_duration = 600  # 10 minutes

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Generating images...", total=total_duration)
            while True:
                elapsed = int(time.time() - start_wait)
                if elapsed > total_duration:
                    raise TimeoutError(ERROR_TIMEOUT)
                progress.update(task, completed=elapsed)
                try:
                    response = self.session.get(polling_url, timeout=30)
                    if response.status_code != 200:
                        raise NoImagesError(ERROR_NORESULTS)
                    if response.text and "errorMessage" not in response.text:
                        break
                    time.sleep(1)
                except requests.exceptions.RequestException as e:
                    console.print(f"[bold yellow]⚠️ Polling failed: {str(e)}[/bold yellow]")
                    time.sleep(2)

        image_links = re.findall(r'src="([^"]+)"', response.text)
        normal_image_links = [link.split("?w=")[0] for link in image_links if "?w=" in link]
        normal_image_links = list(set(normal_image_links))
        if not normal_image_links:
            raise NoImagesError(ERROR_NO_IMAGES)
        console.print("[bold green]✓ Images generated successfully![/bold green]")
        return normal_image_links

    def generate_images(self, prompt, download_count=4):
        """Generate and save images for the given prompt.

        Args:
            prompt (str): The description of the images to generate.
            download_count (int): Number of images to download (max 4).

        Returns:
            list: List of saved image file paths.

        Raises:
            BlockedPromptError: If the prompt contains sensitive words.
            InvalidCookieError: If the cookie is invalid.
            NetworkError: If a network error occurs.
            NoImagesError: If no images are generated.
            TimeoutError: If the request times out.
            ValueError: If the prompt is empty or download_count is invalid.
        """
        if not prompt:
            raise ValueError("Prompt cannot be empty.")
        if download_count > 4:
            raise ValueError("Download count cannot exceed 4.")

        # Check sensitive words
        blocked, blocked_word = contains_sensitive_words(prompt, SENSITIVE_WORDS)
        if blocked:
            raise BlockedPromptError(f"Prompt blocked due to sensitive word: '{blocked_word}'.")

        # Verify cookie
        self.test_cookie()

        console.print(f"[bold blue]Generating images for prompt:[/bold blue] {prompt}")
        try:
            url_encoded_prompt = url_encode_prompt(prompt)
            payload = f"q={url_encoded_prompt}&qs=ds"

            # Preload the create page
            preload_response = self.session.get(f"{BING_URL}/images/create", timeout=30)
            if preload_response.status_code == 200:
                self.session.cookies.update(preload_response.cookies)
                console.print("[bold blue]Preloaded page, captured cookies[/bold blue]")

            # Try POST with fallbacks
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

            # Fallback to GET
            image_links = self._fallback_get_images(url_encoded_prompt)
            return self._save_images(image_links, download_count)

        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Network error: {str(e)}")

    def _save_images(self, links, download_count):
        """Save images to the output directory.

        Args:
            links (list): List of image URLs.
            download_count (int): Number of images to download.

        Returns:
            list: List of saved image file paths.

        Raises:
            NetworkError: If downloading an image fails after retries.
        """
        console.print(f"[bold blue]Downloading {min(download_count, len(links))} images to {self.output_dir}...[/bold blue]")
        saved_files = []
        for i, link in enumerate(links[:download_count]):
            for attempt in range(3):
                try:
                    response = requests.get(link, timeout=30)
                    if response.status_code == 200:
                        filename = generate_filename(self.output_dir, i)
                        with open(filename, "wb") as f:
                            f.write(response.content)
                        console.print(f"[bold green]✓ Saved {filename}[/bold green]")
                        saved_files.append(filename)
                        break
                    else:
                        console.print(
                            f"[bold yellow]⚠️ Attempt {attempt + 1}: Failed to download image {i}: "
                            f"HTTP {response.status_code}[/bold yellow]"
                        )
                except requests.exceptions.RequestException as e:
                    console.print(
                        f"[bold yellow]⚠️ Attempt {attempt + 1}: Failed to download image {i}: {str(e)}[/bold yellow]"
                    )
                    if attempt == 2:
                        console.print(f"[bold red]✗ Gave up on image {i} after 3 attempts[/bold red]")
                    time.sleep(2)
        if len(saved_files) < download_count:
            console.print(
                f"[bold yellow]⚠️ Only {len(saved_files)} images saved, less than requested {download_count}[/bold yellow]"
            )
        return saved_files

# --- Command-Line Interface ---

def main():
    """Run the Bing Image Generator CLI."""
    parser = argparse.ArgumentParser(description="Generate images using Bing's image creator")
    parser.add_argument("-U", help="Auth cookie from browser (overrides BING_AUTH_COOKIE env var)", default=None)
    parser.add_argument("--output-dir", help="Output directory (or set BING_OUTPUT_DIR env var)", default=None)
    parser.add_argument("--download-count", help="Number of images to download (max 4)", type=int, default=2)
    parser.add_argument("--quiet", help="Disable pipeline messages", action="store_true")
    args = parser.parse_args()

    if args.download_count > 4:
        console.print("[bold red]✗ Error: The number of downloads must be less than five[/bold red]")
        return

    # Get output directory
    default_dir = "/storage/emulated/0/DCIM/BingImages" if os.name != "nt" else "BingImages"
    output_dir = args.output_dir or os.getenv("BING_OUTPUT_DIR") or get_output_dir(default_dir, args.quiet)

    # Get auth cookie
    auth_cookie = args.U or os.getenv("BING_AUTH_COOKIE") or DEFAULT_AUTH_COOKIE

    # Initialize generator
    generator = BingImageGenerator(auth_cookie, output_dir, args.quiet)

    while True:
        # Prompt for image description
        if not args.quiet:
            console.print(Panel("[bold cyan]Bing Image Generator[/bold cyan]", expand=False))
            console.print("[bold]Enter a description for the images you want to generate.[/bold]")
        prompt = console.input("[bold magenta]Description (e.g., 'A colorful abstract painting'): [/bold magenta]").strip()
        if not prompt:
            console.print("[bold red]✗ Error: No prompt provided. Please enter a valid image description.[/bold red]")
            continue

        try:
            saved_files = generator.generate_images(prompt, args.download_count)
            if not args.quiet:
                console.print(
                    Panel(
                        f"[bold green]Successfully saved {len(saved_files)} images to {output_dir}[/bold green]",
                        expand=False
                    )
                )
                # Display saved files in a table
                table = Table(title="Generated Images", show_header=True, header_style="bold cyan")
                table.add_column("File Path", style="bold")
                for file in saved_files:
                    table.add_row(file)
                console.print(table)
                console.print("[bold blue]💡 Tip: If images don't appear in gallery, refresh the app or check with a file manager.[/bold blue]")

                # Prompt to generate another image
                choice = console.input("[bold yellow]Would you like to generate another image? (y/n): [/bold yellow]").strip().lower()
                if choice not in ('y', 'yes'):
                    break
        except BingImageGenError as e:
            console.print(f"[bold red]✗ Error: {str(e)}[/bold red]")
            if "not writable" in str(e).lower() or "failed to create" in str(e).lower():
                console.print(
                    "[bold blue]💡 Tip: Ensure the application has storage permissions.[/bold blue]"
                )
            # Prompt to try again
            choice = console.input("[bold yellow]Would you like to try another prompt? (y/n): [/bold yellow]").strip().lower()
            if choice not in ('y', 'yes'):
                break
        except Exception as e:
            console.print(f"[bold red]✗ Unexpected error: {str(e)}[/bold red]")
            # Prompt to try again
            choice = console.input("[bold yellow]Would you like to try another prompt? (y/n): [/bold yellow]").strip().lower()
            if choice not in ('y', 'yes'):
                break

if __name__ == "__main__":
    main()
