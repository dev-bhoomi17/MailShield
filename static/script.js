
document.addEventListener("DOMContentLoaded", function () {
    const form = document.querySelector("form");
    const textarea = document.querySelector("textarea");
    const button = document.querySelector("button");

    if (!form || !textarea || !button) {
        return;
    }

    form.addEventListener("submit", function () {
        if (textarea.value.trim() === "") {
            alert("Please paste email headers before analyzing.");
            return;
        }

        button.disabled = true;
        button.textContent = "Analyzing...";
    });
});
