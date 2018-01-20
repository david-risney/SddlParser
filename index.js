function parseQuery(query) {
    return query.split("&").map((entry) => entry.split("=").map(decodeURIComponent)).reduce((current, next) => {
        current[next[0]] = next[1];
        return current;
    }, { })
}

function handleParseButton() {
    parseSddlAsync(document.getElementById("parseinput").value).then((parsedSddl) => {
        document.getElementById("parseoutput").textContent = parsedSddl.join("\n");
    }, (error) => {
        document.getElementById("parseoutput").textContent = "Error: " + error;
    });
}

if (location.search.length) {
    const parsedQuery = parseQuery(location.search.substr(1));
    if (parsedQuery["sddl"]) {
        document.getElementById("parseinput").value = parsedQuery["sddl"];
        handleParseButton();
    }
}

document.getElementById("parse").addEventListener("click", handleParseButton);