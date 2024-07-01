3 methods.. paste into inspect element:
----
  
Method 1 to check for insecure iframe/frame:
window._details = ['iframe', 'frame', 'object', 'embed'].map(type => Array.from(document.querySelectorAll(type)).map((el, index) => `Type: ${type}, Src: ${el.src || 'No src'}, ID: ${el.id || 'No ID, index ' + index}, Class: ${el.className || 'No class'}, HTML: ${el.outerHTML.slice(0, 200)}`)).flat();
if (window._details.length) {
    console.log("Detected framing elements:");
    window._details.forEach(detail => console.log(detail));
} else {
    console.log("No common framing methods detected.");
}



Detected framing elements:
VM700:4 Type: iframe, Src: No src, ID: No ID, index 0, Class: No class, HTML: <iframe height="1" width="1" style="position: absolute; top: 0px; left: 0px; border: none; visibility: hidden;"></iframe>




Method 2 to check for insecure iframe/frame:
window._details = ['iframe', 'frame', 'object', 'embed'].map(type => Array.from(document.querySelectorAll(type)).map((el, index) => `Type: ${type}, Src: ${el.src || 'No src'}, ID: ${el.id || 'No ID, index ' + index}, Class: ${el.className || 'No class'}, HTML: ${el.outerHTML.slice(0, 50)}\n`)).flat().join(''); window._details.length ? alert("Detected framing elements:\n" + window._details) : alert("No common framing methods detected.");






Method 3 to check for insecure iframe/frame:
window._details = ['iframe', 'frame', 'object', 'embed'].map(type => Array.from(document.querySelectorAll(type)).map((el, index) => {
    return {
        Type: type,
        Src: el.src || 'No src',
        ID: el.id || `No ID, index ${index}`,
        Class: el.className || 'No class',
        HTML: el.outerHTML
    };
})).flat();

if (window._details.length) {
    console.log("Detected framing elements:");
    window._details.forEach(detail => {
        console.log(`Type: ${detail.Type}, Src: ${detail.Src}, ID: ${detail.ID}, Class: ${detail.Class}`);
        console.log(`HTML: ${detail.HTML.substring(0, 200)}`);
        if (detail.HTML.length > 200) {
            for (let i = 200; i < detail.HTML.length; i += 200) {
                console.log(detail.HTML.substring(i, i + 200));
            }
        }
    });
} else {
    console.log("No common framing methods detected.");
}


Output:
Detected framing elements:
VM770:14 Type: iframe, Src: No src, ID: No ID, index 0, Class: No class
VM770:15 HTML: <iframe height="1" width="1" style="position: absolute; top: 0px; left: 0px; border: none; visibility: hidden;"></iframe>
undefined

