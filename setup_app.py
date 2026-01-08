
"""
PayGuard macOS Application Setup
"""
from setuptools import setup

APP = ['payguard_menubar_app.py']
DATA_FILES = [
    ('models', ['trained_models/best_phishing_detector.pkl'] if __import__('os').path.exists('trained_models/best_phishing_detector.pkl') else []),
    ('resources', []),
]

OPTIONS = {
    'argv_emulation': False,
    'plist': {
        'CFBundleName': 'PayGuard',
        'CFBundleDisplayName': 'PayGuard',
        'CFBundleIdentifier': 'com.payguard.app',
        'CFBundleVersion': '3.0.0',
        'CFBundleShortVersionString': '3.0.0',
        'LSMinimumSystemVersion': '10.14.0',
        'LSUIElement': True,  # Menu bar app, no dock icon
        'NSHighResolutionCapable': True,
        'NSAppleEventsUsageDescription': 'PayGuard needs to interact with other apps to scan for threats.',
        'NSCameraUsageDescription': 'PayGuard uses screen capture to scan for visual threats.',
        'SUEnableAutomaticChecks': True,
        'SUFeedURL': 'https://payguard.io/appcast.xml',
    },
    'packages': ['rumps', 'requests', 'PIL', 'sklearn', 'numpy', 'pandas'],
    'includes': ['rumps', 'objc', 'Foundation', 'AppKit'],
    'frameworks': [],
    'iconfile': 'resources/payguard.icns' if __import__('os').path.exists('resources/payguard.icns') else None,
}

setup(
    app=APP,
    name='PayGuard',
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
