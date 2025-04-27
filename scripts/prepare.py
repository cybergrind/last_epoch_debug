#!/usr/bin/env python3
import argparse
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from le_tools.const import LOG_FORMAT


logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
log = logging.getLogger('prepare')

# Constants
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
EXTERNAL_DIR = PROJECT_ROOT / 'external'
INFRA_DIR = PROJECT_ROOT / 'infra'
SCRIPTS_DIR = PROJECT_ROOT / 'scripts'
TOOLS_DIR = PROJECT_ROOT / 'tools'

IL2CPP_REPO_URL = 'https://github.com/Perfare/Il2CppDumper.git'
IL2CPP_RELEASE_URL = 'https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-net6-win-v6.7.46.zip'


def parse_args():
    parser = argparse.ArgumentParser(description='Prepare the project environment')
    parser.add_argument('-f', '--force', action='store_true', help='Force re-downloading and setup')
    parser.add_argument('--skip-clone', action='store_true', help='Skip cloning repositories')
    parser.add_argument('--skip-download', action='store_true', help='Skip downloading releases')
    return parser.parse_args()


def setup_directories():
    """Create the necessary directory structure"""
    log.info('Setting up directory structure...')

    # Create directories if they don't exist
    EXTERNAL_DIR.mkdir(exist_ok=True)
    log.info('Directory structure set up successfully')


def clone_il2cpp_dumper(force=False):
    """Clone the Il2CppDumper repository"""
    target_dir = EXTERNAL_DIR / 'Il2CppDumper'

    if target_dir.exists() and not force:
        log.info(f'Il2CppDumper repository already exists at {target_dir}')
        return

    log.info(f'Cloning Il2CppDumper repository to {target_dir}...')

    if target_dir.exists():
        shutil.rmtree(target_dir)

    try:
        subprocess.run(
            ['git', 'clone', IL2CPP_REPO_URL, str(target_dir)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        log.info('Il2CppDumper repository cloned successfully')
    except subprocess.CalledProcessError as e:
        log.error(f'Failed to clone Il2CppDumper repository: {e}')
        log.error(f'Stdout: {e.stdout.decode()}')
        log.error(f'Stderr: {e.stderr.decode()}')
        sys.exit(1)


def download_il2cpp_dumper_release(force=False):
    """Download the Il2CppDumper release zip"""
    target_dir = EXTERNAL_DIR / 'Il2CppDumper-net6-v6.7.46'

    if target_dir.exists() and not force:
        log.info(f'Il2CppDumper release already exists at {target_dir}')
        return

    log.info(f'Downloading and extracting Il2CppDumper release to {target_dir}...')

    if target_dir.exists():
        shutil.rmtree(target_dir)

    target_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
        temp_path = Path(temp_file.name)

        try:
            # Download the file
            log.info(f'Downloading from {IL2CPP_RELEASE_URL}...')
            urllib.request.urlretrieve(IL2CPP_RELEASE_URL, temp_path)

            # Extract the zip file
            log.info(f'Extracting to {target_dir}...')
            with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                zip_ref.extractall(target_dir)

            log.info('Il2CppDumper release downloaded and extracted successfully')
        except Exception as e:
            log.error(f'Failed to download or extract Il2CppDumper release: {e}')
            sys.exit(1)
        finally:
            # Clean up the temporary file
            if temp_path.exists():
                temp_path.unlink()


def setup_symlinks():
    """Set up symbolic links for .envrc files"""
    log.info('Setting up symbolic links...')

    # Create symlinks for .envrc files
    il2cpp_envrc_src = INFRA_DIR / 'il2cpp_dumper.envrc'
    il2cpp_envrc_dst = EXTERNAL_DIR / 'Il2CppDumper-net6-v6.7.46' / '.envrc'

    wine_custom_envrc_src = INFRA_DIR / 'wine_custom.envrc'
    wine_custom_dir = EXTERNAL_DIR / 'wine_custom'
    wine_custom_dir.mkdir(exist_ok=True)
    wine_custom_envrc_dst = wine_custom_dir / '.envrc'

    # Create the symlinks
    if not il2cpp_envrc_dst.exists():
        os.symlink(il2cpp_envrc_src, il2cpp_envrc_dst)
        log.info(f'Created symlink from {il2cpp_envrc_src} to {il2cpp_envrc_dst}')

    if not wine_custom_envrc_dst.exists():
        os.symlink(wine_custom_envrc_src, wine_custom_envrc_dst)
        log.info(f'Created symlink from {wine_custom_envrc_src} to {wine_custom_envrc_dst}')


def main():
    args = parse_args()

    # Step 1: Set up directories
    setup_directories()

    # Step 2: Clone and download repositories if not skipped
    if not args.skip_clone:
        clone_il2cpp_dumper(force=args.force)

    if not args.skip_download:
        download_il2cpp_dumper_release(force=args.force)

    # Step 3: Set up symbolic links
    setup_symlinks()

    log.info('Environment preparation completed successfully!')
    log.info("Run 'direnv allow' to apply the environment variables if you have direnv installed.")


if __name__ == '__main__':
    main()
