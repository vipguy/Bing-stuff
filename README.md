

# Bing Image Generator

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Dependencies](https://img.shields.io/badge/Dependencies-requests%2C%20rich-yellow)

A Python script to fetch AI-generated images from Bing using a prompt and save them to a specified directory. This tool leverages Bing's image creation API, providing a user-friendly CLI with rich text output, progress bars, and error handling.

## Features
- **Generate AI Images**: Create images using descriptive prompts via Bing's image creator.
- **Rich Output**: Colorful console output with progress bars and tables using the `rich` library.
- **Customizable**: Specify output directory, number of images (up to 4), and authentication cookie.
- **Error Handling**: Robust handling for network issues, blocked prompts, and invalid cookies.
- **Sensitive Word Filtering**: Prevents prompts containing sensitive or prohibited words.
- **Retry Logic**: Automatically retries image downloads on failure (up to 3 attempts).
- **Looping Option**: Prompt to generate more images after each successful run.

## Prerequisites
- **Python 3.6+**: Ensure Python is installed on your system.
- **Dependencies**:
  - `requests`: For making HTTP requests to Bing.
  - `rich`: For enhanced console output (progress bars, tables, etc.).
- **Bing Authentication Cookie**:
  - You need a valid `_U` cookie from `www.bing.com`.
  - Log into `www.bing.com`, open Developer Tools (F12) > Application > Cookies > `https://www.bing.com`, and copy the `_U` cookie **value** (not `_U=`).

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/vipguy/bing-image-generator.git
   cd bing-image-generator
   ```

2. **Install Dependencies**:
   ```bash
   pip install requests rich
   ```

3. **Set Up the Authentication Cookie**:
   - Open `bing_image_gen.py` in a text editor.
   - Replace the `DEFAULT_AUTH_COOKIE` placeholder:
     ```python
     DEFAULT_AUTH_COOKIE = "ADD_YOUR_COOKIE_HERE"
     ```
     with your `_U` cookie value:
     ```python
     DEFAULT_AUTH_COOKIE = "your_cookie_value_here"
     ```
   - Alternatively, set the `BING_AUTH_COOKIE` environment variable or use the `-U` CLI argument (see Usage).

## Usage

### Command-Line Interface (CLI)
Run the script and follow the prompts to generate images.

- **Basic Usage** (uses the hardcoded cookie):
  ```bash
  python bing_image_gen.py --output-dir "images" --download-count 2
  ```
  - Enter a prompt (e.g., "A colorful abstract painting").
  - Choose the output directory (default: `BingImages`).
  - After generation, choose to generate another image or exit.

- **Override Cookie with `-U`**:
  ```bash
  python bing_image_gen.py -U "your_cookie_value" --output-dir "images" --download-count 2
  ```

- **Override Cookie with Environment Variable**:
  ```bash
  export BING_AUTH_COOKIE="your_cookie_value"
  python bing_image_gen.py --output-dir "images" --download-count 2
  ```

- **Quiet Mode** (suppresses interactive prompts and rich output):
  ```bash
  python bing_image_gen.py --output-dir "images" --download-count 2 --quiet
  ```

### Programmatic Usage
Use the `BingImageGenerator` class directly in your Python code.

```python
from bing_image_gen import BingImageGenerator

# Initialize with a cookie and output directory
generator = BingImageGenerator(auth_cookie="your_cookie_value", output_dir="images", quiet=False)

# Generate images
saved_files = generator.generate_images("A futuristic city at night", download_count=2)
print(saved_files)
```

## Output Example
The CLI provides rich output with progress bars and tables:

```
╭─────────────── Bing Image Generator ───────────────╮
│                                                   │
╰───────────────────────────────────────────────────╯
Enter a description for the images you want to generate.
Description (e.g., 'A colorful abstract painting'): A serene mountain landscape

Waiting for Bing to generate images...
Generating images... [██████████                    ]  25%  00:07:30

Downloading 2 images to images...
✓ Saved images/bing_image_20250511_123456_0.png
✓ Saved images/bing_image_20250511_123456_1.png

╭───────────────────────────────────────────────────╮
│ Successfully saved 2 images to images             │
╰───────────────────────────────────────────────────╯
┌──────────────── Generated Images ────────────────┐
│ File Path                                       │
├─────────────────────────────────────────────────┤
│ images/bing_image_20250511_123456_0.png         │
│ images/bing_image_20250511_123456_1.png         │
└─────────────────────────────────────────────────┘
💡 Tip: If images don't appear in gallery, refresh the app or check with a file manager.
Would you like to generate another image? (y/n):
```

## Configuration
- **Sensitive Words**: The script filters prompts for sensitive words (e.g., "violence", "drugs"). Modify `SENSITIVE_WORDS` in the script to adjust the list.
- **Output Directory**: Default is `BingImages` on Windows or `/storage/emulated/0/DCIM/BingImages` on Android. Override with `--output-dir` or `BING_OUTPUT_DIR` environment variable.
- **Download Count**: Defaults to 2 images (max 4). Adjust with `--download-count`.

## Troubleshooting
- **Invalid Cookie**:
  - Error: `Invalid cookie or access denied`.
  - Fix: Update `DEFAULT_AUTH_COOKIE` with a fresh `_U` cookie from `www.bing.com`.
- **Blocked Prompt**:
  - Error: `Prompt blocked due to sensitive word`.
  - Fix: Rephrase the prompt to avoid words in `SENSITIVE_WORDS`.
- **No Images**:
  - Check your internet connection.
  - Ensure the prompt is descriptive and not blocked.
- **Rich Output Issues**:
  - Use a modern terminal (e.g., Windows Terminal, iTerm2) for best rendering.
  - Use `--quiet` to disable rich output if issues persist.

## Limitations
- **Max 4 Images**: Bing limits generation to 4 images per request.
- **NiCd Battery Charger Compatibility**: This script is unrelated to charging batteries, but if you're using it on a device powered by a Black & Decker 18V NiCd battery (e.g., HPB18), ensure you have a compatible charger (e.g., FS18C).
- **Cookie Expiry**: The `_U` cookie may expire; replace it as needed.


## Contributing
Contributions are welcome! Please open an issue or submit a pull request with improvements or bug fixes.

## Author
- **Primal Core**

