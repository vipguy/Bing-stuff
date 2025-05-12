# PrimalcoreBing

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-1.8.4-brightgreen.svg)

A Python Tkinter GUI script to generate AI images using Bing's Image Creator (powered by DALL·E). Generate up to four images per prompt, save them, and view previews with a tap-to-enlarge feature optimized for mobile.

## Features

- Generate AI images from text prompts via Bing.
- Tkinter GUI with logs, results, and image preview tabs.
- Tap/click previews for nearly full-screen view (90% screen size, mobile-friendly).
- Touch-friendly buttons for Android (Pydroid 3).
- Customizable output directory and image count (1–4).
- Runs on Windows, Linux, macOS, and Android.

## Prerequisites

- Python 3.7+ (tested with Pydroid 3 on Android).
- Dependencies: `requests`, `rich`, `pillow`, `tkinter`.
- Bing `_U` cookie (see [Setup](#setup)).
- Android: Storage permissions for Pydroid 3.

## Installation

1. **Clone Repository**:
   ```bash
   git clone https://github.com/vipguy/primalcorebing.git
   cd primalcorebing
Install Dependencies:
bash
pip install requests rich pillow
In Pydroid 3, use the terminal tab.
Tkinter is included; verify it works.
Get Bing Cookie:
Log in to Bing.
Use browser developer tools (F12) to copy the _U cookie.
Replace DEFAULT_AUTH_COOKIE in PrimalcoreBing.py (set to _U=ADD_COOKIE_HERE_) or enter it in the GUI.
Android Permissions:
Settings > Apps > Pydroid 3 > Permissions > Storage > Allow.
Usage
Desktop
Run:
bash
python PrimalcoreBing.py
In GUI:
Enter prompt (e.g., "cosmic galaxy").
Set output directory (default: ./BingImages).
Enter _U cookie.
Select 1–4 images.
Click "Generate Images".
Click previews to enlarge; close with "Close".
Android (Pydroid 3)
Copy PrimalcoreBing.py to device (e.g., /storage/emulated/0/dndpy/primalcore/).
Open in Pydroid 3’s editor; tap "Run".
In GUI:
Enter prompt and settings.
Tap "Generate Images".
Tap previews for nearly full-screen view.
Tap "Close" to dismiss.
Note: Avoid sensitive words (e.g., "porn", "violence") to prevent prompt blocking.
Troubleshooting
SyntaxError: Ensure script is fully copied. Check indentation (4 spaces). Compare with repository.
GUI Fails (Pydroid 3): Run in editor, not terminal. Test Tkinter:
python
import tkinter as tk
root = tk.Tk()
tk.Label(root, text="Test").pack()
root.mainloop()
Small Enlarged View: Uses 90% screen size. Share resolution (e.g., 1080x1920) for adjustments.
InvalidCookieError: Update _U cookie in script or GUI.
Permission Denied: Use /data/user/0/ru.iiec.pydroid3/files/BingImages.
Contributing
Fork, create a branch, commit changes, and open a pull request. Suggestions: pinch-to-zoom, swipe navigation.
License
MIT License. See LICENSE.
Acknowledgments
Uses Tkinter, Pillow.
Powered by Bing’s Image Creator (DALL·E).


     MIT License

     Copyright (c) 2025 Primal Core

     Permission is hereby granted, free of charge, to any person obtaining a copy
     of this software and associated documentation files (the "Software"), to deal
     in the Software without restriction, including without limitation the rights
     to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
     copies of the Software, and to permit persons to whom the Software is
     furnished to do so, subject to the following conditions:

     The above copyright notice and this permission notice shall be included in all
     copies or substantial portions of the Software.

     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
     IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
     AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
     LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
     OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
     SOFTWARE.
