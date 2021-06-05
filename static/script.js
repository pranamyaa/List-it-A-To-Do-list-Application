'use strict';

window.addEventListener('load', function () {
});

function toggleeditform(button) {
    let formdiv = button.nextElementSibling
    if (formdiv.style.display === "none") {
        formdiv.style.display = ""
    } else {
        formdiv.style.display = "none"
    }
}

function confirmdelete(tasktype) {
    return confirm('Are you sure you want to delete this '+tasktype+'?')
}