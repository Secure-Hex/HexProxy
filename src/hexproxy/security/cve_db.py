from __future__ import annotations

CVE_DATABASE: dict[str, dict[str, list[dict[str, str]]]] = {
    "jquery": {
        "3.4.0": [
            {
                "id": "CVE-2020-11022",
                "description": "Improper input validation in jQuery allows XSS through HTML insertion methods.",
            },
            {
                "id": "CVE-2020-11023",
                "description": "Input sanitization bypass in jQuery causes XSS when using jQuery.html().",
            },
        ],
        "3.3.1": [
            {
                "id": "CVE-2019-11358",
                "description": "Prototype pollution via the jQuery.extend functionality when in the Sizzle selector engine.",
            }
        ],
    },
    "express": {
        "4.16.0": [
            {
                "id": "CVE-2017-16138",
                "description": "Buffer overflow in express.js before 4.17.1 allows DoS via crafted "
                "`urlencoded` bodies.",
            }
        ],
    },
}
