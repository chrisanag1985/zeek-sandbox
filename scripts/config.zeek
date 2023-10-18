module SandBox;


export {
    type API: enum { WILDFIRE , CUCKOO };



    # https://github.com/zeek/zeek/tree/master/scripts/base/frameworks/files/magic

    type MIME_TYPE: enum { 
                           FILE_PE,
                           FILE_PDF,
                           FILE_MSWORD,
                           FILE_RAR,
                           FILE_GZIP,
                           FILE_OOXML,
                           FILE_DOCX,
                           FILE_XLSX,
                           FILE_PPTX
         };

    type Info: record 
    {
          conn: connection &log &optional;
          f: fa_file &log &optional;
          # HASH or URL
          indicator: string &log;
          indicator_type: MIME_TYPE &log;
          sandbox: API &log &optional;
          # Worker which found it
          node_name: string &log &optional;
    };


}

type VERDICT: enum { BENIGN , MALICIOUS, ERROR , PENDING , UNKNOWN };
type verdict_record: record 
{
    verdict: VERDICT &optional;
    api_verdict: string;
    sandbox: API;
};

# because one uid may have a lot files
type info_index: record
{
    uid: string;
    indicator: string;
    fuid: string;
};


const mime_type_table: table[SandBox::MIME_TYPE] of string= {

                [FILE_PE] = "application/x-dosexec",
                [FILE_PDF] = "application/pdf",
                [FILE_MSWORD] = "application/msword",
                [FILE_RAR] = "application/x-rar",
                [FILE_GZIP] = "applicaiton/x-gzip",
                [FILE_OOXML] = "application/vnd.openxmlformats-officedocument",
                [FILE_DOCX] = "application/vnd.openxmlformats-officedocument.wordproccessingml.document",
                [FILE_XLSX] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                [FILE_PPTX] = "application/vnd.openxmlformats-officedocument.presentationml.presentation"

};

