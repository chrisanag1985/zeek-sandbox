@load base/utils/active-http
@load ../config

module SandBox;
# Must not be exported? bind with variables from main?
export {
    option WILDFIRE_API_KEY = "<API-KEY>" ;
    option WILDFIRE_PROTOCOL = "https";
    option WILDFIRE_SERVER = "<ip or hostname>";
    option WILDFIRE_VERIFY_TLS = T;
}

const get_verdict = "/publicapi/get/verdict" &redef;
const submit_file = "/publicapi/submit/file" &redef;

const wildfire_verdict_malicious: set[string]  = {"1","2","3","4","5"};
const wildfire_verdict_analysis: table[string] of string = {
       ["0"]= "Benign",
       ["1"]= "Malware",
       ["2"]= "Grayware",
       ["4"]= "Phishing",
       ["5"]= "C2",
       ["-100"]= "Pending, the sample exists, but there is currently no verdict",
       ["-101"]= "Error",
       ["-102"]= "Unknown, cannot find sample record in the database",
       ["-103"]= "Invalid hash value"
 };

 
const wildfire_status_codes: table[count] of string = {

	[200]= "OK",
	[401]= "Invalid API key",
	[403]= "Forbidden",
	[404]= "Not Found",
	[405]= "Unsupported Method",
	[413]= "Request Entity Too Large",
	[418]= "Unsupported File Type",
	[419]= "Max Request Reached",
	[420]= "Insufficient Arguments",
	[421]= "Invalid Argument",
	[422]= "Unprocessable Entities",
	[500]= "Internal Error Internal error.",
	[513]= "File upload failed.",
};


function wildfire_submit_hash(hash: string): verdict_record{

    local url: string = fmt("%s://%s%s",WILDFIRE_PROTOCOL,WILDFIRE_SERVER,get_verdict); 
    local data: string = "";
    local result: verdict_record;
    result$sandbox =  SandBox::WILDFIRE;
    
    if (WILDFIRE_VERIFY_TLS)
    {
        data = fmt("-F apikey=%s -F hash=%s",WILDFIRE_API_KEY,hash);
    }
    else
    {

        data = fmt("-k -F apikey=%s -F hash=%s",WILDFIRE_API_KEY,hash);
    }

    local request = ActiveHTTP::Request($url=url,$method="POST",$addl_curl_args=data);

    # Add Zeek version checking

    return when [request,result] (local response = ActiveHTTP::request($req = request))
    {
            if (response?$code)
            {
                if (response$code == 200)
                {
                    #Reporter::info(fmt("Hash Response: %s",response));
                    local verdict = match_pattern(response$body,/<verdict>[-]?[0-9]{1,3}<\/verdict>/);
                    local verdict_result = verdict$str[9:-10];
                    #Reporter::info(fmt("Verdict: %s",verdict_result));
                    # Verdict return must be something same in all Sandbox APIs. So some mapping
                    # must be happen here
                    if (verdict_result in wildfire_verdict_malicious)
                    {
                        result$verdict = SandBox::MALICIOUS;
                        result$api_verdict = wildfire_verdict_analysis[verdict_result];
                    }
                    if (verdict_result == "0")
                    {
                        result$verdict = SandBox::BENIGN;
                        result$api_verdict = wildfire_verdict_analysis[verdict_result];
                    }
                    if (verdict_result == "-100")
                    {
                        result$verdict = SandBox::PENDING;
                        result$api_verdict = wildfire_verdict_analysis[verdict_result];
                    }
                    if (verdict_result == "-102")
                    {
                        result$verdict = SandBox::UNKNOWN;
                        result$api_verdict = wildfire_verdict_analysis[verdict_result];
                    }
                    if (verdict_result == "-101" || verdict_result == "-103")
                    {
                        result$verdict = SandBox::ERROR;
                        result$api_verdict = wildfire_verdict_analysis[verdict_result];
                    }

                    return result;

                }

                # print error based on status code
                # Make it more analytic
                if(response$code != 200)
                {
                    Reporter::error(fmt("Error: %s",wildfire_status_codes[response$code]));
                    result$verdict = SandBox::ERROR;
                    result$api_verdict = wildfire_status_codes[response$code];
                    result$sandbox = SandBox::WILDFIRE;
                    return result;
                }
            }
       
    }


}

function wildfire_submit_file(filename: string): bool
{
    local url: string = fmt("%s://%s%s",WILDFIRE_PROTOCOL,WILDFIRE_SERVER,submit_file); 
    local data: string = "";
    
    if (WILDFIRE_VERIFY_TLS)
    {
        data = fmt("-F apikey=%s -F file=@./extract_files/%s",WILDFIRE_API_KEY,filename);
    }
    else
    {

        data = fmt("-k -F apikey=%s -F file=@./extract_files/%s",WILDFIRE_API_KEY,filename);
    }


    local request = ActiveHTTP::Request($url=url,$method="POST",$addl_curl_args=data);
    return when [filename,request] (local response = ActiveHTTP::request($req = request))
        {
                if (response?$code)
                {
                    if (response$code == 200)
                    {
                        #Reporter::info(cat(response));
                        return T;
                    }
                    # something is happening here on error - non-void function returning
                    # without a value (priv error unsupporterd file type) 
                    Reporter::error(fmt("Error in submitting the file: %s  Error Code: %s Error: %s",filename,response$code,wildfire_status_codes[response$code]));
                    return F;
                    
                }
                return F;
        }
}