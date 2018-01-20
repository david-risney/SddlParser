importScripts("sddlparser.js");

onmessage = (msg) => {
    try {
        console.log("worker: parse `" + msg.data.sddlToParse + "`");
        const result = sddlParser.parse(msg.data.sddlToParse);
        console.log("worker: parse result " + JSON.stringify(result));
        postMessage({
            parseIndex: msg.data.parseIndex,
            resolve: true,
            result
        });
    }
    catch (error) {
        console.error("worker: error " + error.message + " " + error.stack);
        postMessage({
            parseIndex: msg.data.parseIndex,
            resolve: false,
            result: error
        });
    }
};