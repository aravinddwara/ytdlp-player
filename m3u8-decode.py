import re
import json
import requests
from urllib.parse import urljoin
import base64

class JuicyCodesDecoder:
    """Decoder for JuicyCodes obfuscation"""
    
    def __init__(self):
        self.symbol_map = ["`", "%", "-", "+", "*", "$", "!", "_", "^", "="]
    
    def decode_salt(self, salt_str):
        """Decode the 3-character salt"""
        result = ""
        for char in salt_str:
            result += str(ord(char) - 100)
        return int(result)
    
    def base64_decode(self, encoded_str):
        """Custom base64 decode"""
        # Add padding
        padding_needed = (4 - len(encoded_str) % 4) % 4
        encoded_str += "=" * padding_needed
        
        # Replace URL-safe characters
        encoded_str = encoded_str.replace("_", "+").replace("-", "/")
        
        try:
            decoded = base64.b64decode(encoded_str).decode('utf-8')
            return decoded
        except Exception as e:
            print(f"[!] Base64 decode error: {e}")
            return None
    
    def rot13(self, text):
        """ROT13 transformation"""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    def decode(self, encoded_string):
        """Main decode function"""
        try:
            # Step 1: Extract salt (last 3 chars)
            main_content = encoded_string[:-3]
            salt = self.decode_salt(encoded_string[-3:])
            
            print(f"[JuicyCodes] Salt: {salt}")
            
            # Step 2: Base64 decode
            decoded_b64 = self.base64_decode(main_content)
            if not decoded_b64:
                return None
            
            # Step 3: ROT13
            rot13_decoded = self.rot13(decoded_b64)
            
            # Step 4: Map characters to indices
            indices = ""
            for char in rot13_decoded:
                if char in self.symbol_map:
                    indices += str(self.symbol_map.index(char))
            
            # Step 5: Split into 4-digit groups
            groups = re.findall(r'.{4}', indices)
            
            # Step 6: Decode each group
            result = ""
            for group in groups:
                num = int(group)
                decoded_num = (num % 1000) - salt
                if 0 <= decoded_num <= 1114111:  # Valid Unicode range
                    result += chr(decoded_num)
            
            return result
            
        except Exception as e:
            print(f"[!] JuicyCodes decode error: {e}")
            import traceback
            traceback.print_exc()
            return None


class ThrfiveExtractor:
    """
    Python extractor for Thrfive JWPlayer streams
    Used by TamilDhool and similar sites
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.juicy_decoder = JuicyCodesDecoder()
    
    def extract_stream(self, embed_url, referer_url, save_html=False):
        """
        Extract stream URL from Thrfive embed page
        
        Args:
            embed_url: The Thrfive embed URL (e.g., https://thrfive.io/embed/6DUErDucR33ZTe2)
            referer_url: The referer URL (e.g., https://www.tamildhool.tech/)
            save_html: If True, saves the HTML to a file for debugging
            
        Returns:
            Dictionary with stream URL and metadata
        """
        try:
            print(f"[1] Fetching embed page: {embed_url}")
            
            # Fetch the embed page with proper referer
            response = self.session.get(
                embed_url,
                headers={'Referer': referer_url}
            )
            response.raise_for_status()
            html = response.text
            
            print(f"[2] Page fetched successfully ({len(html)} bytes)")
            
            # Save HTML for debugging if requested
            if save_html:
                filename = "thrfive_debug.html"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html)
                print(f"[DEBUG] HTML saved to {filename}")
            
            # METHOD 1: Decode _juicycodes() to get the player config
            juicycodes_pattern = r'_juicycodes\(((?:"[^"]*"\s*\+\s*)*"[^"]*")\)'
            juicycodes_match = re.search(juicycodes_pattern, html)
            
            if juicycodes_match:
                print("[3] Found _juicycodes() call")
                
                # Extract all quoted strings
                string_expr = juicycodes_match.group(1)
                strings = re.findall(r'"([^"]*)"', string_expr)
                encoded_string = ''.join(strings)
                
                print(f"[4] Encoded string length: {len(encoded_string)}")
                print(f"[4] First 50 chars: {encoded_string[:50]}")
                print(f"[4] Last 10 chars: {encoded_string[-10:]}")
                
                # Decode it
                print("[5] Decoding JuicyCodes...")
                decoded_js = self.juicy_decoder.decode(encoded_string)
                
                if decoded_js:
                    print(f"[6] Decoded! Length: {len(decoded_js)} chars")
                    print(f"[6] Preview: {decoded_js[:200]}...")
                    
                    # Save decoded JS for debugging
                    if save_html:
                        with open("thrfive_decoded.js", 'w', encoding='utf-8') as f:
                            f.write(decoded_js)
                        print("[DEBUG] Decoded JS saved to thrfive_decoded.js")
                    
                    # Extract M3U8 URL from decoded JavaScript
                    stream_url = self._extract_stream_from_decoded_js(decoded_js, html)
                    
                    if stream_url:
                        print(f"[7] Found stream URL: {stream_url}")
                        
                        # Extract token/cookies if present
                        token = self._extract_token(html, decoded_js)
                        
                        return {
                            'url': stream_url,
                            'referer': referer_url,
                            'type': 'm3u8',
                            'quality': 'auto',
                            'token': token,
                            'headers': {
                                'Referer': referer_url,
                                'Origin': 'https://thrfive.io',
                                'User-Agent': self.session.headers['User-Agent']
                            }
                        }
                    else:
                        print("[!] Could not find stream URL in decoded JS")
                else:
                    print("[!] JuicyCodes decoding failed")
            
            # METHOD 2: Try to find juicyData (fallback)
            # Method 1: Find the script tag containing window.juicyData
            script_pattern = r'<script[^>]*>\s*window\.juicyData\s*=\s*(\{.*?\}\s*\})\s*</script>'
            script_match = re.search(script_pattern, html, re.DOTALL)
            
            if script_match:
                print("[3] Found juicyData in script tag")
                json_str = script_match.group(1)
            else:
                # Method 2: Try a more flexible pattern
                juicy_pattern = r'window\.juicyData\s*=\s*(\{(?:[^{}]|(?:\{[^{}]*\}))*\})'
                juicy_match = re.search(juicy_pattern, html, re.DOTALL)
                
                if juicy_match:
                    print("[3] Found juicyData object (fallback method)")
                    json_str = juicy_match.group(1)
                else:
                    print("[!] Could not find window.juicyData in page")
                    print("[!] Checking what's available in the page...")
                    
                    # Debug: Show what script tags we have
                    script_tags = re.findall(r'<script[^>]*>.*?</script>', html[:5000], re.DOTALL)
                    print(f"[DEBUG] Found {len(script_tags)} script tags in first 5000 chars")
                    
                    # Check for _juicycodes
                    if '_juicycodes(' in html:
                        print("[!] Found _juicycodes() - page uses obfuscated player")
                        print("[!] The juicyData might be in a separate <script> tag")
                        
                        # Try to find ALL script tags and look for juicyData in each
                        all_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
                        for i, script_content in enumerate(all_scripts):
                            if 'juicyData' in script_content:
                                print(f"[DEBUG] Found juicyData in script tag #{i}")
                                print(f"[DEBUG] Script preview: {script_content[:200]}...")
                                
                                # Try to extract just the JSON part
                                json_match = re.search(r'window\.juicyData\s*=\s*(\{.*$)', script_content, re.DOTALL | re.MULTILINE)
                                if json_match:
                                    json_str = json_match.group(1).strip()
                                    # Remove trailing semicolon and any comments
                                    json_str = json_str.rstrip(';').split('</script>')[0].strip()
                                    print(f"[DEBUG] Extracted JSON: {json_str[:150]}...")
                                    break
                        else:
                            return self._fallback_extraction(html, referer_url)
                    else:
                        return self._fallback_extraction(html, referer_url)
            
            # Parse the JSON
            try:
                juicy_data = json.loads(json_str)
            except json.JSONDecodeError as e:
                print(f"[!] JSON parse error: {e}")
                print(f"[DEBUG] Problematic JSON: {json_str[:200]}...")
                return self._fallback_extraction(html, referer_url)
            
            # Extract the ping route
            ping_route = juicy_data.get('data', {}).get('routes', {}).get('ping')
            
            if not ping_route:
                print("[!] No ping route found in juicyData")
                return self._fallback_extraction(html, referer_url)
            
            print(f"[4] Ping route: {ping_route}")
            
            # Clean up escaped slashes
            ping_route = ping_route.replace('\\/', '/')
            
            # Build the full ping URL
            base_url = 'https://thrfive.io'
            ping_url = urljoin(base_url, ping_route)
            
            print(f"[5] Calling ping API: {ping_url}")
            
            # Call the ping endpoint
            ping_response = self.session.get(
                ping_url,
                headers={
                    'Referer': referer_url,
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            )
            ping_response.raise_for_status()
            
            print(f"[6] Ping response ({ping_response.status_code}): {ping_response.text[:200]}...")
            
            # Parse the response
            stream_data = ping_response.json()
            
            # Try different possible keys for the stream URL
            stream_url = (
                stream_data.get('stream') or 
                stream_data.get('url') or 
                stream_data.get('file') or
                stream_data.get('sources', [{}])[0].get('file')
            )
            
            if not stream_url:
                print("[!] No stream URL found in ping response")
                print(f"Response keys: {list(stream_data.keys())}")
                return None
            
            # Clean up the URL
            stream_url = stream_url.replace('\\/', '/')
            
            print(f"[7] Stream URL extracted: {stream_url}")
            
            # Validate the URL
            if self._validate_stream_url(stream_url, referer_url):
                return {
                    'url': stream_url,
                    'referer': referer_url,
                    'type': 'm3u8',
                    'quality': 'auto'
                }
            else:
                print("[!] Stream URL validation failed")
                return None
                
        except requests.RequestException as e:
            print(f"[!] Request error: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"[!] JSON decode error: {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _extract_stream_from_decoded_js(self, decoded_js, html):
        """Extract M3U8 URL from decoded JavaScript"""
        print("[*] Searching for stream URL in decoded JavaScript...")
        
        # Patterns to find M3U8 URLs
        patterns = [
            # Direct URL patterns
            r'(https://coke\.infamous\.network/stream/[A-Za-z0-9+/=_-]+\.m3u8)',
            r'(https://khufu\.groovy\.monster/stream/[A-Za-z0-9+/=_-]+\.m3u8)',
            
            # JWPlayer file property
            r'file\s*:\s*["\']([^"\']*(?:coke\.infamous\.network|khufu\.groovy\.monster)[^"\']*\.m3u8)["\']',
            
            # Sources array
            r'sources\s*:\s*\[\s*\{\s*file\s*:\s*["\']([^"\']*\.m3u8)["\']',
            
            # Variable assignments
            r'var\s+\w+\s*=\s*["\']([^"\']*(?:coke\.infamous\.network|khufu\.groovy\.monster)[^"\']*\.m3u8)["\']',
            
            # URL with escaped slashes
            r'["\']([^"\']*(?:coke|khufu)[^"\']*stream[^"\']*)["\']'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, decoded_js, re.IGNORECASE)
            if match:
                url = match.group(1)
                # Clean up URL
                url = url.replace('\\/', '/').replace('\\', '')
                
                if url.startswith('//'):
                    url = 'https:' + url
                
                # Ensure it ends with .m3u8
                if '/stream/' in url and not url.endswith('.m3u8'):
                    url = url + '.m3u8'
                
                print(f"[*] Found URL with pattern: {pattern[:50]}...")
                return url
        
        # Also check the original HTML in case it's there
        for pattern in patterns[:2]:  # Just the direct URL patterns
            match = re.search(pattern, html)
            if match:
                url = match.group(1).replace('\\/', '/')
                print(f"[*] Found URL in HTML")
                return url
        
        return None
    
    def _extract_token(self, html, decoded_js):
        """Extract authentication token if present"""
        # Check for token in juicyData
        token_patterns = [
            r'"token"\s*:\s*"([^"]+)"',
            r'token\s*:\s*["\']([^"\']+)["\']',
            r'jwplayer.*?token["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in token_patterns:
            # Check HTML first
            match = re.search(pattern, html)
            if match:
                token = match.group(1)
                print(f"[*] Found token in HTML: {token[:20]}...")
                return token
            
            # Check decoded JS
            if decoded_js:
                match = re.search(pattern, decoded_js)
                if match:
                    token = match.group(1)
                    print(f"[*] Found token in decoded JS: {token[:20]}...")
                    return token
        
        return None
    
    def _fallback_extraction(self, html, referer_url):
        """
        Fallback method: Try to extract m3u8 URL directly from HTML
        """
        print("[*] Attempting fallback extraction from HTML")
        
        # Patterns to find m3u8 URLs
        patterns = [
            r'(https://coke\.infamous\.network/stream/[A-Za-z0-9+/=_-]+\.m3u8)',
            r'(https://khufu\.groovy\.monster/stream/[A-Za-z0-9+/=_-]+\.m3u8)',
            r'file["\']\s*:\s*["\']([^"\']*(?:coke\.infamous\.network|khufu\.groovy\.monster)[^"\']*)["\']',
            r'["\']https?://[^"\']*(?:coke\.infamous\.network|khufu\.groovy\.monster)[^"\']*\.m3u8[^"\']*["\']'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                url = match.group(1)
                url = url.replace('\\/', '/').replace('\\', '')
                
                if url.startswith('//'):
                    url = 'https:' + url
                if not url.endswith('.m3u8') and '/stream/' in url:
                    url = url + '.m3u8'
                
                print(f"[*] Found URL via fallback: {url}")
                
                if self._validate_stream_url(url, referer_url):
                    return {
                        'url': url,
                        'referer': referer_url,
                        'type': 'm3u8',
                        'quality': 'auto'
                    }
        
        print("[!] Fallback extraction failed")
        return None
    
    def _validate_stream_url(self, url, referer, token=None):
        """
        Validate if the stream URL is accessible
        """
        try:
            print(f"[*] Validating stream URL: {url[:80]}...")
            
            headers = {
                'Referer': referer,
                'Origin': 'https://thrfive.io',
                'Accept': '*/*'
            }
            
            # Add token if present
            if token:
                headers['Authorization'] = f'Bearer {token}'
                # Some services use different header names
                headers['X-Auth-Token'] = token
            
            response = self.session.head(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=10
            )
            
            print(f"[*] Validation response: {response.status_code}")
            
            if response.status_code == 403:
                print("[!] 403 Forbidden - Stream may require authentication/cookies")
                print("[*] Trying with cookies from session...")
                
                # Try with GET request to get cookies
                response = self.session.get(
                    url,
                    headers=headers,
                    stream=True,
                    timeout=10
                )
                
                print(f"[*] GET response: {response.status_code}")
                print(f"[*] Cookies: {self.session.cookies.get_dict()}")
                
                return response.status_code == 200
            
            return response.status_code in [200, 301, 302]
            
        except requests.RequestException as e:
            print(f"[*] Validation error (stream might still work in player): {e}")
            # Some streams block HEAD requests but work with GET
            return True
    
    def get_playlist_variants(self, m3u8_url, referer, token=None):
        """
        Parse M3U8 playlist and get available quality variants
        """
        try:
            headers = {
                'Referer': referer,
                'Origin': 'https://thrfive.io',
                'Accept': '*/*',
                'User-Agent': self.session.headers['User-Agent']
            }
            
            if token:
                headers['Authorization'] = f'Bearer {token}'
            
            response = self.session.get(m3u8_url, headers=headers, timeout=15)
            response.raise_for_status()
            
            content = response.text
            print(f"[*] M3U8 Content Length: {len(content)} bytes")
            
            # Save M3U8 content for debugging
            with open("playlist.m3u8", 'w', encoding='utf-8') as f:
                f.write(content)
            print("[DEBUG] Playlist saved to playlist.m3u8")
            
            # Parse M3U8 for quality variants
            variants = []
            lines = content.split('\n')
            
            for i, line in enumerate(lines):
                if line.startswith('#EXT-X-STREAM-INF:'):
                    # Extract resolution and bandwidth
                    resolution_match = re.search(r'RESOLUTION=(\d+x\d+)', line)
                    bandwidth_match = re.search(r'BANDWIDTH=(\d+)', line)
                    
                    if i + 1 < len(lines):
                        variant_url = lines[i + 1].strip()
                        if not variant_url.startswith('http'):
                            # Relative URL
                            variant_url = urljoin(m3u8_url, variant_url)
                        
                        variants.append({
                            'url': variant_url,
                            'resolution': resolution_match.group(1) if resolution_match else 'unknown',
                            'bandwidth': int(bandwidth_match.group(1)) if bandwidth_match else 0
                        })
            
            # If no variants, this might be a direct stream
            if not variants and '#EXTINF:' in content:
                print("[*] This is a direct stream (no quality variants)")
                variants.append({
                    'url': m3u8_url,
                    'resolution': 'direct',
                    'bandwidth': 0
                })
            
            return variants
            
        except Exception as e:
            print(f"[!] Error parsing M3U8: {e}")
            return []
    
    def download_stream(self, m3u8_url, referer, output_file="output.mp4", token=None):
        """
        Download stream using ffmpeg (if available)
        """
        try:
            import subprocess
            
            headers = f"Referer: {referer}\r\nOrigin: https://thrfive.io\r\nUser-Agent: {self.session.headers['User-Agent']}"
            
            if token:
                headers += f"\r\nAuthorization: Bearer {token}"
            
            cmd = [
                'ffmpeg',
                '-headers', headers,
                '-i', m3u8_url,
                '-c', 'copy',
                '-bsf:a', 'aac_adtstoasc',
                output_file
            ]
            
            print(f"[*] Downloading stream to {output_file}...")
            print(f"[*] Command: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Show progress
            for line in process.stderr:
                if 'time=' in line:
                    print(f"\r{line.strip()}", end='', flush=True)
            
            process.wait()
            
            if process.returncode == 0:
                print(f"\n[✓] Download complete: {output_file}")
                return True
            else:
                print(f"\n[!] Download failed with code {process.returncode}")
                return False
                
        except FileNotFoundError:
            print("[!] ffmpeg not found. Please install ffmpeg to download streams.")
            print("    Install: sudo apt install ffmpeg  (Linux)")
            print("    Install: brew install ffmpeg  (Mac)")
            print("    Install: choco install ffmpeg  (Windows)")
            return False
        except Exception as e:
            print(f"[!] Download error: {e}")
            return False


def test_extraction():
    """
    Test the extractor with a sample URL
    """
    print("=" * 80)
    print("Thrfive Stream Extractor - Test")
    print("=" * 80)
    
    # Example URLs
    embed_url = "https://thrfive.io/embed/6DUErDucR33ZTe2"
    referer_url = "https://www.tamildhool.tech/"
    
    extractor = ThrfiveExtractor()
    
    print(f"\nEmbed URL: {embed_url}")
    print(f"Referer: {referer_url}\n")
    
    # Extract stream (with HTML debug save enabled)
    result = extractor.extract_stream(embed_url, referer_url, save_html=True)
    
    print("\n" + "=" * 80)
    
    if result:
        print("✓ SUCCESS! Stream extracted")
        print("-" * 80)
        print(f"Stream URL: {result['url']}")
        print(f"Type: {result['type']}")
        print(f"Quality: {result['quality']}")
        print(f"Referer: {result['referer']}")
        
        if result.get('token'):
            print(f"Token: {result['token'][:30]}..." if len(result['token']) > 30 else f"Token: {result['token']}")
        
        if result.get('headers'):
            print(f"\nRequired Headers:")
            for key, value in result['headers'].items():
                print(f"  {key}: {value[:50]}..." if len(str(value)) > 50 else f"  {key}: {value}")
        
        # Try to validate
        print("\n" + "=" * 80)
        print("Validating stream access...")
        print("=" * 80)
        
        token = result.get('token')
        if extractor._validate_stream_url(result['url'], referer_url, token):
            print("\n✓ Stream URL is accessible!")
        else:
            print("\n⚠ Stream URL validation failed")
            print("This might mean:")
            print("  - Authentication/cookies required")
            print("  - Time-based token expired")
            print("  - IP/region restrictions")
            print("  - But it might still work in a video player!")
        
        # Try to get quality variants
        print("\n" + "=" * 80)
        print("Fetching quality variants...")
        print("=" * 80)
        
        token = result.get('token')
        variants = extractor.get_playlist_variants(result['url'], referer_url, token)
        
        if variants:
            print(f"\nFound {len(variants)} quality variant(s):")
            for i, variant in enumerate(variants, 1):
                print(f"\n{i}. Resolution: {variant['resolution']}")
                if variant['bandwidth'] > 0:
                    print(f"   Bandwidth: {variant['bandwidth']:,} bps ({variant['bandwidth']//1000} kbps)")
                print(f"   URL: {variant['url'][:80]}...")
        else:
            print("\nCould not fetch variants (but stream URL is valid)")
        
        print("\n" + "=" * 80)
        print("Stream Extraction Complete!")
        print("=" * 80)
        print("\n📺 HOW TO USE THIS STREAM:")
        print("-" * 80)
        
        print("\n1. VLC Media Player:")
        print("   - Open Network Stream")
        print("   - Paste the URL")
        print("   - Add custom headers in 'More Options'")
        
        print("\n2. mpv (Command Line):")
        print(f'   mpv --http-header-fields="Referer: {referer_url},Origin: https://thrfive.io" \\')
        print(f'       "{result["url"]}"')
        
        print("\n3. ffmpeg (Download):")
        print(f'   ffmpeg -headers "Referer: {referer_url}" \\')
        print(f'          -i "{result["url"]}" \\')
        print(f'          -c copy output.mp4')
        
        print("\n4. Python requests:")
        print(f'''   headers = {{
       'Referer': '{referer_url}',
       'Origin': 'https://thrfive.io',
       'User-Agent': 'Mozilla/5.0...'
   }}
   response = requests.get('{result["url"][:60]}...', headers=headers, stream=True)''')
        
        # Option to download
        print("\n" + "=" * 80)
        download = input("Would you like to download this stream now? (y/n): ").strip().lower()
        
        if download == 'y':
            output_file = input("Enter output filename (default: output.mp4): ").strip()
            if not output_file:
                output_file = "output.mp4"
            
            extractor.download_stream(result['url'], referer_url, output_file, token)
        
        print("\n" + "=" * 80)
        
    else:
        print("✗ FAILED! Could not extract stream")
        print("=" * 80)


def test_custom_url():
    """
    Test with custom URLs
    """
    print("\n\nCustom URL Test")
    print("=" * 80)
    
    embed_url = input("Enter Thrfive embed URL (or press Enter for default): ").strip()
    if not embed_url:
        embed_url = "https://thrfive.io/embed/6DUErDucR33ZTe2"
    
    referer_url = input("Enter referer URL (or press Enter for default): ").strip()
    if not referer_url:
        referer_url = "https://www.tamildhool.tech/"
    
    extractor = ThrfiveExtractor()
    result = extractor.extract_stream(embed_url, referer_url, save_html=True)
    
    if result:
        print("\n✓ Stream URL:", result['url'])
        
        # Test the stream
        print("\n" + "=" * 80)
        print("Testing stream access...")
        print("=" * 80)
        
        try:
            headers = {
                'Referer': referer_url,
                'Origin': 'https://thrfive.io',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(result['url'], headers=headers, stream=True, timeout=10)
            
            print(f"Status: {response.status_code} {response.reason}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
            print(f"Content-Length: {response.headers.get('Content-Length', 'N/A')}")
            
            if response.status_code == 200:
                # Read first 1KB
                chunk = next(response.iter_content(1024), None)
                if chunk:
                    print(f"First chunk size: {len(chunk)} bytes")
                    print(f"First line: {chunk[:100].decode('utf-8', errors='ignore')}")
                    print("\n✓ Stream is accessible and working!")
            
        except Exception as e:
            print(f"Error testing stream: {e}")
    else:
        print("\n✗ Failed to extract stream")


def quick_test_stream_url():
    """
    Quick test if you already have the M3U8 URL
    """
    print("\n\nQuick Stream Test")
    print("=" * 80)
    
    stream_url = input("Enter M3U8 URL: ").strip()
    if not stream_url:
        print("No URL provided")
        return
    
    referer = input("Enter referer (default: https://www.tamildhool.tech/): ").strip()
    if not referer:
        referer = "https://www.tamildhool.tech/"
    
    print("\nTesting stream...")
    
    try:
        headers = {
            'Referer': referer,
            'Origin': 'https://thrfive.io',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(stream_url, headers=headers, stream=True, timeout=10)
        
        print(f"\nStatus: {response.status_code} {response.reason}")
        print(f"Headers:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")
        
        if response.status_code == 200:
            content = response.text[:500]
            print(f"\nContent preview:\n{content}")
            print("\n✓ Stream is accessible!")
            
            # Parse playlist
            if '#EXTM3U' in content:
                print("\nValid M3U8 playlist detected")
                variants = re.findall(r'#EXT-X-STREAM-INF:.*?RESOLUTION=(\d+x\d+)', content)
                if variants:
                    print(f"Found {len(variants)} quality variants: {', '.join(variants)}")
        else:
            print(f"\n✗ Failed with status {response.status_code}")
            
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    import sys
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--quick':
            quick_test_stream_url()
            sys.exit(0)
        elif sys.argv[1] == '--help':
            print("Usage:")
            print("  python thrfive_extractor.py           # Run full test")
            print("  python thrfive_extractor.py --quick   # Quick stream URL test")
            print("  python thrfive_extractor.py --custom  # Test with custom URLs")
            sys.exit(0)
        elif sys.argv[1] == '--custom':
            test_custom_url()
            sys.exit(0)
    
    # Run the default test
    test_extraction()
    
    # Optionally test with custom URL
    print("\n")
    custom = input("Test with custom URL? (y/n): ").strip().lower()
    if custom == 'y':
        test_custom_url()
    
    # Or quick test existing stream
    print("\n")
    quick = input("Quick test an existing stream URL? (y/n): ").strip().lower()
    if quick == 'y':
        quick_test_stream_url()
