// Include stylesheet
document.write("<link rel=\"stylesheet\" type=\"text/css\" href=\"CSS/default.css\">");

// Include navbar
document.write(
    "<!-- Navbar -->" +
    "<div id=\"navbar\">" +
    "<a href=\"home.html\">" +
    "<button>Home</button>" +
    "</a>" +
    "<a href=\"calendar.html\">" +
    "<button>Calendar</button>" +
    "</a>" +
    "<a href=\"members.html\">" +
    "<button>Members</button>" +
    "</a>" +
    "<a href=\"resources.html\">" +
    "<button>Resources</button>" +
    "</a>" +
    "<a>" +
    "<button onclick=\"snackbar()\">Blog</button>" +
    "</a>" +
    "<div id=\"snackbar\">This has yet to be completed</div>" +


    "</div>");

function snackbar() {
    // Get the snackbar DIV ew
    var x = document.getElementById("snackbar");

    // Add the "show" class to DIV
    x.className = "show";

    // After 3 seconds, remove the show class from DIV
    setTimeout(function () {
        x.className = x.className.replace("show", "");
    }, 3000);
}
