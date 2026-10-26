
exports.handler = async function(event) {
    if(event.httpMethod !== "POST"){
        return {
            statusCode:405,
            body:JSON.stringify({error:"Method not allowed"})
        };
    }

    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if(!apiKey){
        return {
            statusCode:503,
            body:JSON.stringify({
                error:"Threat checking is not configured. Add the Google Safe Browsing API key in Netlify."
            })
        };
    }

    try{
        const body = JSON.parse(event.body || "{}");
        const url = String(body.url || "").trim();

        let site;

        try{
            site = new URL(url);
        }
        catch{
            return {
                statusCode:400,
                body:JSON.stringify({error:"Invalid URL"})
            };
        }

        if(
            (site.protocol !== "https:" &&
             site.protocol !== "http:") ||
            !site.hostname.includes(".") ||
            site.username ||
            site.password
        ){
            return {
                statusCode:400,
                body:JSON.stringify({error:"Invalid or unsupported URL"})
            };
        }

        // Check the URL against Google's known threat lists.
        const response = await fetch(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
            encodeURIComponent(apiKey),
            {
                method:"POST",
                headers:{
                    "Content-Type":"application/json"
                },
                body:JSON.stringify({
                    client:{
                        clientId:"cyberonline-portal",
                        clientVersion:"1.0"
                    },
                    threatInfo:{
                        threatTypes:[
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"
                        ],
                        platformTypes:["ANY_PLATFORM"],
                        threatEntryTypes:["URL"],
                        threatEntries:[{url:site.href}]
                    }
                })
            }
        );

        if(!response.ok){
            console.error(
                "Safe Browsing request failed:",
                response.status
            );

            return {
                statusCode:502,
                body:JSON.stringify({
                    error:"The threat database check failed. Please try again later."
                })
            };
        }

        const data = await response.json();
        const matches = data.matches || [];

        let score = 0;
        let flags = [];

        // A known threat is the strongest warning.
        if(matches.length > 0){
            score = 100;

            matches.forEach(match=>{
                flags.push(
                    "Google Safe Browsing reported a known threat: " +
                    String(match.threatType || "Threat detected") +
                    "."
                );
            });
        }
        else{
            // Apply consistent URL warning rules as well.
            const host = site.hostname.toLowerCase();
            const fullURL = site.href.toLowerCase();

            function addRisk(points,message){
                score += points;
                flags.push(message);
            }

            if(site.protocol === "http:"){
                addRisk(
                    15,
                    "The connection uses HTTP rather than HTTPS."
                );
            }

            if(host.includes("xn--")){
                addRisk(
                    20,
                    "The domain uses encoded international characters."
                );
            }

            if(/^(\d{1,3}\.){3}\d{1,3}$/.test(host)){
                addRisk(
                    20,
                    "The website uses an IP address instead of a domain name."
                );
            }

            if(host.length > 50){
                addRisk(
                    10,
                    "The hostname is unusually long."
                );
            }

            if(host.split(".").length > 5){
                addRisk(
                    10,
                    "The domain has an unusually large number of subdomains."
                );
            }

            const suspiciousWords = [
                "free-prize",
                "account-verify",
                "password-reset",
                "secure-login",
                "urgent-payment"
            ];

            const foundWords = suspiciousWords.filter(
                word => fullURL.includes(word)
            );

            if(foundWords.length > 0){
                addRisk(
                    Math.min(foundWords.length * 10,20),
                    "Potentially suspicious URL patterns found: " +
                    foundWords.join(", ") + "."
                );
            }

            score = Math.min(score,70);
        }

        let verdict;

        if(matches.length > 0){
            verdict = "Known Threat Detected";
        }
        else if(score >= 40){
            verdict = "High Apparent Risk";
        }
        else if(score >= 15){
            verdict = "Warning";
        }
        else{
            verdict = "No Known Threat Detected";
        }

        if(flags.length === 0){
            flags.push(
                "Google Safe Browsing reported no known threat for this URL. " +
                "This does not guarantee the website is safe."
            );
        }

        return {
            statusCode:200,
            headers:{
                "Content-Type":"application/json"
            },
            body:JSON.stringify({
                score:score,
                verdict:verdict,
                flags:flags,
                summary:
                    matches.length > 0
                    ? "A known threat was reported by Google Safe Browsing. Avoid interacting with this website."
                    : "No known threat was reported by Google Safe Browsing. Additional URL warning checks were applied, but this is not a full security audit.",
                checkedBy:"Google Safe Browsing and URL warning rules",
                threatMatch:matches.length > 0
            })
        };
    }
    catch(error){
        console.error("Scan error:",error.message);

        return {
            statusCode:500,
            body:JSON.stringify({
                error:"The scan could not be completed."
            })
        };
    }
};
