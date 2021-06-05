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
    var taskadditional = ''
    if (tasktype == 'task') {
        taskadditional = '\nAny subtask existing will be deleted too.'
    }
    return confirm('Are you sure you want to delete this ' + tasktype + '?' + taskadditional)
}

function removeimgcheckbox(checkbox) {
    let fileinput = checkbox.previousElementSibling.previousElementSibling
    if (checkbox.checked == true) {
        fileinput.value = ''
    }
}

function changeimg(fileinput) {
    let checkbox = fileinput.nextElementSibling.nextElementSibling
    checkbox.checked = false
}
