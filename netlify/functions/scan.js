exports.handler = async function(event){
    const headers = {
        "Content-Type":"application/json",
        "Cache-Control":"no-store"
    };

    function reply(statusCode,data){
        return {
            statusCode:statusCode,
            headers:headers,
            body:JSON.stringify(data)
        };
    }

    if(event.httpMethod !== "POST"){
        return reply(405,{
            error:"Use POST to scan a URL."
        });
    }

    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if(!apiKey){
        return reply(503,{
            error:"Google Safe Browsing is not configured in Netlify."
        });
    }

    let url;
    let site;

    try{
        const body = JSON.parse(event.body || "{}");

        if(typeof body.url !== "string" || !body.url.trim()){
            return reply(400,{
                error:"A URL is required."
            });
        }

        url = body.url.trim();

        if(!/^https?:\/\//i.test(url)){
            url = "https://" + url;
        }

        site = new URL(url);

        if(
            (site.protocol !== "https:" && site.protocol !== "http:") ||
            !site.hostname.includes(".") ||
            site.username ||
            site.password
        ){
            return reply(400,{
                error:"Please provide a valid public website URL."
            });
        }

        url = site.href;
    }
    catch(error){
        return reply(400,{
            error:"The URL is invalid."
        });
    }

    // Ask Google Safe Browsing about this exact URL.
    let googleData;

    try{
        const endpoint =
            "https://safebrowsing.googleapis.com/v4/threatMatches:find" +
            "?key=" + encodeURIComponent(apiKey);

        const googleResponse = await fetch(endpoint,{
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
                    threatEntries:[{url:url}]
                }
            })
        });

        if(!googleResponse.ok){
            console.error(
                "Google Safe Browsing HTTP status:",
                googleResponse.status
            );

            return reply(502,{
                error:"Google Safe Browsing could not complete the check. Check the API configuration and try again."
            });
        }

        googleData = await googleResponse.json();
    }
    catch(error){
        console.error("Google Safe Browsing request failed:",error);

        return reply(502,{
            error:"Google Safe Browsing is temporarily unavailable."
        });
    }

    // A Google threat match is the strongest signal in this report.
    const matches = Array.isArray(googleData.matches)
        ? googleData.matches
        : [];

    if(matches.length > 0){
        const threatTypes = [
            ...new Set(matches.map(match => match.threatType))
        ];

        return reply(200,{
            score:100,
            verdict:"Known Threat Detected",
            source:"Google Safe Browsing",
            flags:[
                "Google Safe Browsing identified a known threat match.",
                "Threat categories: " + threatTypes.join(", ") + "."
            ],
            summary:
                "Google Safe Browsing reported this URL as a known threat. " +
                "Avoid entering personal information or downloading files from it."
        });
    }

    // Google returned no known threat match.
    // Apply additional, consistent URL warning rules.
    let score = 0;
    const flags = [];

    function addRisk(points,message){
        score += points;
        flags.push(message);
    }

    const host = site.hostname.toLowerCase();
    const fullURL = url.toLowerCase();

    if(site.protocol === "http:"){
        addRisk(
            15,
            "The URL uses HTTP instead of HTTPS."
        );
    }

    const isIPv4 =
        /^(\d{1,3}\.){3}\d{1,3}$/.test(host);

    const isIPv6 = host.includes(":");

    if(isIPv4 || isIPv6){
        addRisk(
            20,
            "The URL uses an IP address instead of a regular domain name."
        );
    }

    if(host.includes("xn--")){
        addRisk(
            25,
            "The domain contains encoded international characters that deserve inspection."
        );
    }

    if(site.port && site.port !== "80" && site.port !== "443"){
        addRisk(
            10,
            "The URL uses a nonstandard web port."
        );
    }

    const suspiciousWords = [
        "verify",
        "password",
        "signin",
        "login",
        "account",
        "wallet",
        "urgent",
        "gift",
        "free-prize"
    ];

    const foundWords = [];

    suspiciousWords.forEach(word=>{
        if(fullURL.includes(word)){
            foundWords.push(word);
        }
    });

    if(foundWords.length > 0){
        addRisk(
            Math.min(foundWords.length * 8,20),
            "Potentially sensitive or deceptive terms appear in the URL: " +
            foundWords.join(", ") +
            ". These words alone do not prove a threat."
        );
    }

    if(host.length > 50){
        addRisk(
            5,
            "The hostname is unusually long."
        );
    }

    if(host.split(".").length > 5){
        addRisk(
            10,
            "The domain has an unusually large number of subdomains."
        );
    }

    score = Math.min(score,100);

    let verdict;

    if(score === 0){
        verdict = "No Known Threats Detected";
    }
    else if(score <= 20){
        verdict = "Can't Confirm";
    }
    else if(score <= 50){
        verdict = "Warning";
    }
    else{
        verdict = "High URL Risk Indicators";
    }

    if(flags.length === 0){
        flags.push(
            "Google Safe Browsing returned no known threat match."
        );

        flags.push(
            "No warning signs were found by the additional URL checks."
        );
    }

    let summary;

    if(score === 0){
        summary =
            "Google Safe Browsing returned no known threat match, " +
            "and the additional URL checks found no warning signs. " +
            "This does not guarantee that the website is safe.";
    }
    else{
        summary =
            "Google Safe Browsing returned no known threat match, " +
            "but the URL checks identified characteristics that deserve " +
            "additional inspection. The score represents URL warning " +
            "indicators, not the probability that the site is malicious. " +
            "A threat can exist without appearing in a known threat list.";
    }

    return reply(200,{
        score:score,
        verdict:verdict,
        source:"Google Safe Browsing + URL checks",
        flags:flags,
        summary:summary
    });
};
