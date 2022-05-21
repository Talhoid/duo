var checkbox = document.querySelector('input[name="theme"]');
checkbox.addEventListener('change', function() {
    if (this.checked) {
        darkmode.setDarkMode(true)
    } else {
        darkmode.setDarkMode(false);
    }
});
darkmode.inDarkMode ? checkbox.checked = true : checkbox.checked = false;