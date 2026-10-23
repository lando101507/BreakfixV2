document.addEventListener("DOMContentLoaded", function () {
    const loader = document.getElementById("breakfix-loader");

    if (!loader) return;

    const minimumLoadingTime = 2500;
    const startTime = Date.now();
    let pageLoaded = document.readyState === "complete";

    function hideWhenReady() {
        if (!pageLoaded) return;

        const elapsed = Date.now() - startTime;
        const remaining = Math.max(0, minimumLoadingTime - elapsed);

        setTimeout(function () {
            loader.classList.add("hide");
        }, remaining);
    }

    // Wait until the page finishes loading
    if (!pageLoaded) {
        window.addEventListener("load", function () {
            pageLoaded = true;
            hideWhenReady();
        }, { once: true });
    } else {
        hideWhenReady();
    }

    // Show loader when opening another page
    document.addEventListener("click", function (event) {
        const link = event.target.closest("a");

        if (!link) return;
        if (link.target === "_blank") return;
        if (link.hasAttribute("download")) return;

        if (
            event.ctrlKey ||
            event.metaKey ||
            event.shiftKey ||
            event.altKey
        ) return;

        const url = new URL(link.href, window.location.href);

        if (url.origin !== window.location.origin) return;

        if (
            url.pathname === window.location.pathname &&
            url.search === window.location.search
        ) return;

        loader.classList.remove("hide");
    });

    // Show loader when submitting a form
    document.addEventListener("submit", function (event) {
        const form = event.target;

        if (!form || form.target === "_blank") return;

        loader.classList.remove("hide");
    });
});