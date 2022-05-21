/* start dependencies */

class DarkMode{constructor(){this._hasGDPRConsent=!1,this.cookieExpiry=365,"loading"===document.readyState?document.addEventListener("DOMContentLoaded",function(){DarkMode.onDOMContentLoaded()}):DarkMode.onDOMContentLoaded()}get inDarkMode(){return DarkMode.getColorScheme()==DarkMode.VALUE_DARK}set inDarkMode(a){this.setDarkMode(a,!1)}get hasGDPRConsent(){return this._hasGDPRConsent}set hasGDPRConsent(a){if(this._hasGDPRConsent=a,a){const a=DarkMode.readCookie(DarkMode.DATA_KEY);a&&(DarkMode.saveCookie(DarkMode.DATA_KEY,"",-1),localStorage.setItem(DarkMode.DATA_KEY,a))}else{const a=localStorage.getItem(DarkMode.DATA_KEY);a&&(localStorage.removeItem(DarkMode.DATA_KEY),DarkMode.saveCookie(DarkMode.DATA_KEY,a))}}get documentRoot(){return document.getElementsByTagName("html")[0]}static saveCookie(a,b="",c=365){let d="";if(c){const a=new Date;a.setTime(a.getTime()+1e3*(60*(60*(24*c)))),d="; expires="+a.toUTCString()}document.cookie=a+"="+b+d+"; SameSite=Strict; path=/"}saveValue(a,b,c=this.cookieExpiry){this.hasGDPRConsent?DarkMode.saveCookie(a,b,c):localStorage.setItem(a,b)}static readCookie(a){const b=a+"=",c=document.cookie.split(";");for(let d=0;d<c.length;d++){const a=c[d].trim();if(a.startsWith(b))return a.substring(b.length)}return""}readValue(a){if(this.hasGDPRConsent)return DarkMode.readCookie(a);else{const b=localStorage.getItem(a);return b?b:""}}eraseValue(a){this.hasGDPRConsent?this.saveValue(a,"",-1):localStorage.removeItem(a)}getSavedColorScheme(){const a=this.readValue(DarkMode.DATA_KEY);return a?a:""}getPreferedColorScheme(){return window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches?DarkMode.VALUE_DARK:window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches?DarkMode.VALUE_LIGHT:""}setDarkMode(a,b=!0){const c=document.querySelectorAll("[data-"+DarkMode.DATA_SELECTOR+"]");if(0==c.length)a?(this.documentRoot.classList.remove(DarkMode.CLASS_NAME_LIGHT),this.documentRoot.classList.add(DarkMode.CLASS_NAME_DARK)):(this.documentRoot.classList.remove(DarkMode.CLASS_NAME_DARK),this.documentRoot.classList.add(DarkMode.CLASS_NAME_LIGHT));else for(let b=0;b<c.length;b++)c[b].setAttribute("data-"+DarkMode.DATA_SELECTOR,a?DarkMode.VALUE_DARK:DarkMode.VALUE_LIGHT);b&&this.saveValue(DarkMode.DATA_KEY,a?DarkMode.VALUE_DARK:DarkMode.VALUE_LIGHT)}toggleDarkMode(a=!0){let b;const c=document.querySelector("[data-"+DarkMode.DATA_SELECTOR+"]");b=c?c.getAttribute("data-"+DarkMode.DATA_SELECTOR)==DarkMode.VALUE_DARK:this.documentRoot.classList.contains(DarkMode.CLASS_NAME_DARK),this.setDarkMode(!b,a)}resetDarkMode(){this.eraseValue(DarkMode.DATA_KEY);const a=this.getPreferedColorScheme();if(a)this.setDarkMode(a==DarkMode.VALUE_DARK,!1);else{const a=document.querySelectorAll("[data-"+DarkMode.DATA_SELECTOR+"]");if(0==a.length)this.documentRoot.classList.remove(DarkMode.CLASS_NAME_LIGHT),this.documentRoot.classList.remove(DarkMode.CLASS_NAME_DARK);else for(let b=0;b<a.length;b++)a[b].setAttribute("data-"+DarkMode.DATA_SELECTOR,"")}}static getColorScheme(){const a=document.querySelector("[data-"+DarkMode.DATA_SELECTOR+"]");if(!a)return darkmode.documentRoot.classList.contains(DarkMode.CLASS_NAME_DARK)?DarkMode.VALUE_DARK:darkmode.documentRoot.classList.contains(DarkMode.CLASS_NAME_LIGHT)?DarkMode.VALUE_LIGHT:"";else{const b=a.getAttribute("data-"+DarkMode.DATA_SELECTOR);return b==DarkMode.VALUE_DARK||b==DarkMode.VALUE_LIGHT?b:""}}static updatePreferedColorSchemeEvent(){let a=darkmode.getSavedColorScheme();a||(a=darkmode.getPreferedColorScheme(),a&&darkmode.setDarkMode(a==DarkMode.VALUE_DARK,!1))}static onDOMContentLoaded(){let a=darkmode.readValue(DarkMode.DATA_KEY);a||(a=DarkMode.getColorScheme(),!a&&(a=darkmode.getPreferedColorScheme()));const b=a==DarkMode.VALUE_DARK;darkmode.setDarkMode(b,!1),window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change",function(){DarkMode.updatePreferedColorSchemeEvent()})}}DarkMode.DATA_KEY="bs.prefers-color-scheme",DarkMode.DATA_SELECTOR="bs-color-scheme",DarkMode.VALUE_LIGHT="light",DarkMode.VALUE_DARK="dark",DarkMode.CLASS_NAME_LIGHT="light",DarkMode.CLASS_NAME_DARK="dark";
const darkmode=new DarkMode;

/* end dependencies */ 

var checkbox = document.querySelector('input[name="theme"]');
checkbox.addEventListener('change', function() {
    if (this.checked) {
        darkmode.setDarkMode(true)
    } else {
        darkmode.setDarkMode(false);
    }
});
darkmode.inDarkMode ? checkbox.checked = true : checkbox.checked = false;