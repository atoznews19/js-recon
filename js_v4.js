// ==UserScript==
// @name         JS Recon Loader (GitHub)
// @namespace    https://github.com/atoznews19/js-recon
// @version      1.0.0
// @description  Loads JS Recon v3 from GitHub - auto-updates when you push changes
// @author       atoznews19
// @license      MIT
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @run-at       document-end
// @homepageURL  https://github.com/atoznews19/js-recon
// @supportURL   https://github.com/atoznews19/js-recon/issues
// @updateURL    https://github.com/atoznews19/js-recon/raw/main/js-recon-loader.user.js
// ==/UserScript==

(function() {
    'use strict';

    // ================================================================
    //  CONFIG - Change these to match your GitHub repo
    // ================================================================
    var CONFIG = {
        // URL to the raw recon code on GitHub
        CODE_URL: 'https://raw.githubusercontent.com/atoznews19/js-recon/main/src/recon-core.js',
        
        // Check for updates every 24 hours (in milliseconds)
        UPDATE_INTERVAL: 86400000, // 24 hours
        
        // Version to display
        VERSION: '1.0.0',
    };

    // ================================================================
    //  LOADER FUNCTIONS
    // ================================================================

    function loadFromGitHub() {
        console.log('[JS Recon Loader] Fetching recon code from GitHub...');
        console.log('[JS Recon Loader] URL:', CONFIG.CODE_URL);

        GM_xmlhttpRequest({
            method: 'GET',
            url: CONFIG.CODE_URL,
            timeout: 30000,
            onload: function(response) {
                if (response.status === 200) {
                    console.log('[JS Recon Loader] Code fetched successfully (' + response.responseText.length + ' bytes)');
                    executeReconCode(response.responseText);
                } else {
                    console.error('[JS Recon Loader] Failed to fetch code. Status:', response.status);
                    console.error('[JS Recon Loader] Falling back to local version...');
                    // Fallback: try to load from a local backup or display error
                    showErrorMessage('Failed to load JS Recon from GitHub. Check your internet connection and the GitHub URL.\nStatus: ' + response.status);
                }
            },
            onerror: function(error) {
                console.error('[JS Recon Loader] Network error:', error);
                showErrorMessage('Network error loading JS Recon from GitHub. Check your internet connection.\nError: ' + (error.error || 'Unknown error'));
            },
            ontimeout: function() {
                console.error('[JS Recon Loader] Request timeout.');
                showErrorMessage('Timeout loading JS Recon from GitHub. The server may be slow or unavailable.');
            }
        });
    }

    function executeReconCode(code) {
        try {
            // Wrap the code in a function to execute it in the page context
            var wrapper = new Function(code);
            wrapper.call(window);
            console.log('[JS Recon Loader] Recon code executed successfully.');
        } catch (error) {
            console.error('[JS Recon Loader] Error executing recon code:', error);
            showErrorMessage('Error executing JS Recon code:\n' + error.message);
        }
    }

    function showErrorMessage(message) {
        // Create a visible error notification on the page
        var container = document.createElement('div');
        container.style.cssText = [
            'position: fixed',
            'bottom: 80px',
            'right: 20px',
            'z-index: 2147483647',
            'background: #1a0a0a',
            'color: #ff6666',
            'border: 1px solid #ff3333',
            'border-radius: 8px',
            'padding: 12px 16px',
            'max-width: 400px',
            'font-family: monospace',
            'font-size: 12px',
            'box-shadow: 0 4px 20px rgba(0,0,0,0.8)',
            'white-space: pre-wrap',
            'word-break: break-word',
        ].join(';');
        container.textContent = '⚠️ JS Recon Error: ' + message;
        document.body.appendChild(container);

        // Auto-remove after 15 seconds
        setTimeout(function() {
            if (container.parentNode) container.parentNode.removeChild(container);
        }, 15000);
    }

    // ================================================================
    //  UPDATE CHECK
    // ================================================================

    function checkForUpdates() {
        console.log('[JS Recon Loader] Checking for updates...');
        // This is a simple check - you can enhance it by comparing versions
        GM_xmlhttpRequest({
            method: 'GET',
            url: CONFIG.CODE_URL + '?t=' + Date.now(), // Bypass cache
            timeout: 10000,
            onload: function(response) {
                if (response.status === 200) {
                    // Check if the code contains a version string
                    var versionMatch = response.responseText.match(/VERSION:\s*['"]([^'"]+)['"]/);
                    if (versionMatch) {
                        console.log('[JS Recon Loader] GitHub version:', versionMatch[1]);
                        // You could compare with current version and reload if newer
                    }
                }
            },
            onerror: function() {
                // Silent fail for update checks
            }
        });
    }

    // ================================================================
    //  INITIALISE
    // ================================================================

    // Check for update immediately, then periodically
    checkForUpdates();
    setInterval(checkForUpdates, CONFIG.UPDATE_INTERVAL);

    // Load the recon code from GitHub
    loadFromGitHub();

    console.log('[JS Recon Loader] v' + CONFIG.VERSION + ' loaded.');
    console.log('[JS Recon Loader] Fetching JS Recon from:', CONFIG.CODE_URL);

})();
