@load base/frameworks/files
@load base/files/hash
@load base/frameworks/notice
@load base/utils/active-http 
@load ./config
@load ./sandbox_apis/wildfire







module SandBox;

## ADD IS CLUSTER  ENABLED

export {

    redef enum Notice::Type += {
		## This notice is generated when an intelligence
		## indicator is denoted to be notice-worthy.
		SandBox::Notice
	};

   # Make it multi Sandbox 
   option prefered_sandbox = SandBox::WILDFIRE;

   option max_rechecks = 3;

   option recheck_interval = 60sec;

   option cache_expire_interval = 48hr;

   option delete_benign = T;

   const default_verdict: SandBox::VERDICT =  SandBox::BENIGN  &redef; 

   const mime_type_analysis: set[SandBox::MIME_TYPE] = set() &redef; 
   
   # TODO add Hooks to the right places
   global malicious_hash_found: hook(info: SandBox::Info);

   global malicious_file_found: hook(info: SandBox::Info);


}
# end of export

# table of info_index record 
global info_store: table[info_index] of SandBox::Info &broker_allow_complex_type &backend=Broker::MEMORY;
#table of hash | ideally only on PROXY
global hash_times_rechecked: table[string] of count &backend=Broker::MEMORY;
# Create Cache for 24hr? Persists in Manager? Loaded from there?
global distributed_cache: table[string] of verdict_record &broker_allow_complex_type &backend=Broker::SQLITE &create_expire=cache_expire_interval;

global _mime_type_analysis: set[string] = set();
global _default_verdict : SandBox::verdict_record;

## Add LOG Stream and init it 

global send_file_to_sandbox:  event(info: SandBox::Info);
global send_hash_to_sandbox:  event(info: SandBox::Info);
global recheck_for_verdict: event();
global delete_file: event(info: SandBox::Info);



event enable_timer()
{
    #@if ( Cluster::get_node_count(Cluster::PROXY) == 1)
    #    Broker::publish(Cluster::proxy_topic,recheck_for_verdict);
    #@else 
    #    local random = rand($max=10);
    #    Cluster::publish_hrw(Cluster::proxy_pool,random,recheck_for_verdict);
    #@endif

    local random = rand($max=10);
    Cluster::publish_hrw(Cluster::proxy_pool,random,recheck_for_verdict);

    schedule recheck_interval { enable_timer() };

}


event zeek_init() 
{
    #Dynamic load based on Sandbox of preference
    # TODO check if info_store not 0 and schedule a hash check? for persistant store

    _default_verdict$verdict = default_verdict;
    _default_verdict$api_verdict = "not_set";

    for ( m in mime_type_analysis)
    {
        add _mime_type_analysis[mime_type_table[m]];
    }

    # Start scheduler
    @if ( !Cluster::is_enabled() || (Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER))
            schedule recheck_interval { enable_timer() };
    @endif

}

function get_mime(mime: string): MIME_TYPE
{
    for (i in mime_type_table)
    {
        if (mime_type_table[i] == mime){
            return i;
        }
    }
}


function _send_hash_to_sandbox(hash: string): SandBox::verdict_record
{
    # here i have to check for the function to ask for hash
    # based on sandbox
    return when [hash] (local a = wildfire_submit_hash(hash))
    {
        #Reporter::info(fmt("Hash: %s Verdict: %s API Verdict:%s From %s",hash,a$verdict,a$api_verdict,a$sandbox));
        return a;
    }
}




function do_notice(item: SandBox::Info, verdict: SandBox::verdict_record)
{
                local n: Notice::Info = Notice::Info(
                    $note=SandBox::Notice,
                    $conn=item$conn,
                    $f = item$f,
                    $suppress_for = 0sec,
                    $msg=fmt("%s file found from %s",verdict$verdict,
                    verdict$sandbox),
                    $sub=fmt("File Hash: %s Extracted Name: %s at Node: %s",
                    item$indicator,
                    item$f$info$extracted,
                    item$node_name
                    )
                    );

               	NOTICE(n);
}


function lookup_info_store(indicator: string, verdict: SandBox::verdict_record)
{

    local found: set[info_index] = set();
    for (index in info_store)
    {
        if (indicator == index$indicator)
        {
            switch verdict$verdict 
            {
                case SandBox::BENIGN:
                    add found[index]; 
                    break;
                case SandBox::MALICIOUS:
            
                    # Raise notice
                    do_notice(info_store[index],verdict);
                    add found[index]; 
                    break;
            
                case SandBox::UNKNOWN:
                    add found[index]; 
                    break;
                    #TODO
                    #same as benigh but maybe i want to add hook?
                    #leave it for now in order to check what went 
                    #wrong if the number is to big
                default:
                    Reporter::info(fmt("Lookup info store case :%s",verdict$verdict));
                    break;
            }

        }

    }
    if (|found| > 0){
        for (i in found)
        {
            if ((verdict$verdict == SandBox::BENIGN || verdict$verdict == SandBox::UNKNOWN )&& delete_benign)
                Broker::publish(Cluster::worker_topic,delete_file,info_store[i]);
            delete info_store[i];
        }
        delete hash_times_rechecked[indicator];
    }

}




event recheck_for_verdict(){

    local size = |hash_times_rechecked|;
    local size_table = |info_store|;
    #Reporter::info(fmt("Running on %s => Size of hashes awaiting: %s Size of Sandbox table: %s",Cluster::node,size,size_table));

    if (size == 0){
        return;
    }

    for ( i in hash_times_rechecked)
    {
            #Reporter::info(fmt("Indicator Recheck %s from %s",i,Cluster::node));
            when [i] (local v  = _send_hash_to_sandbox(i))
            {
                        switch v$verdict{

                             case SandBox::MALICIOUS:

                                distributed_cache[i] = v;
                                lookup_info_store(i,v);
                                break;

                             case SandBox::BENIGN:

                                distributed_cache[i] = v;
                                lookup_info_store(i,v);
                                break;

                             case SandBox::PENDING:

                                hash_times_rechecked[i] = hash_times_rechecked[i]+1;
                                # Do not recheck for ever
                                if ( hash_times_rechecked[i] > max_rechecks )
                                {
                                    lookup_info_store(i,_default_verdict);
                                }
                                break;

                            # A failsafe because i issued problems here
                            case SandBox::UNKNOWN:
                           
                                # Why it enters here because we have submitted the file
                                lookup_info_store(i,v);
                                break;

                            default: 

                                Reporter::info(fmt("Recheck case :%s",v$verdict));
                                break;
                        }
            }
            

    }
}


# Running in WORKERS
event delete_file(info: SandBox::Info)
{
    if ( Cluster::node != info$node_name)
        return;

    local del_command : Exec::Command;
    del_command = [$cmd=fmt("rm -f ./extract_files/%s",info$f$info$filename)];

    when [del_command]  ( local result = Exec::run($cmd=del_command))
    {
        #Reporter::info(fmt("Delete file %s",info$f$info$filename));
    }
}


# Running in WORKERS
event send_file_to_sandbox(info: SandBox::Info)
{

    if ( Cluster::node != info$node_name)
        return;
        
    #Reporter::info(fmt("Current Worker: %s Hash: %s Desired-Worker: %s  Ready to send file: %s",Cluster::node,info$indicator,info$node_name,info$extracted_name));
    when [info] ( local b = wildfire_submit_file(info$f$info$extracted))
    {

            if (!b)
            {
                Reporter::warning(fmt("Error for hash: %s file: %s with file type: %s",info$indicator,info$f$info$extracted,info$indicator_type));
            }
            else
            {    
                local index: info_index = [ $uid=info$conn$uid , $indicator=info$indicator , $fuid = info$f$id];
                info_store[index] = info;
                # if HASH?
                hash_times_rechecked[info$indicator] = 0;
            }

    }
}

# RUNNING in PROXIES
event send_hash_to_sandbox(info: SandBox::Info)
{

    local hash = info$indicator;
    local index: info_index;

    if ( hash in hash_times_rechecked)
    {
        # Hash exists in hashes for check
        index = [ $uid=info$conn$uid , $indicator=info$indicator , $fuid = info$f$id];
        info_store[index] = info;
        return;
    }


    #Reporter::info(fmt("Running on: %s Got hash: %s from worker: %s",Cluster::node,hash,info$node_name));
    
    when [info,index] (local v = _send_hash_to_sandbox(info$indicator))
    {

        switch v$verdict {
            
            case SandBox::UNKNOWN:

                # is there anyway to return 2 times UNKNOWN?
                Broker::publish(Cluster::worker_topic,send_file_to_sandbox,info);
                break;
                
            case SandBox::MALICIOUS:

                distributed_cache[info$indicator] = v;
                do_notice(info,v);
                break;

             case SandBox::PENDING:

                #Reporter::warning(fmt("Pending state for hash: %s",info$indicator));
                index = [ $uid=info$conn$uid , $indicator=info$indicator , $fuid = info$f$id];
                info_store[index] = info;
                break;

             case SandBox::BENIGN:

                distributed_cache[info$indicator] = v;
                if (delete_benign)
                    Broker::publish(Cluster::worker_topic,delete_file,info);
                break;
        
             default:

                Reporter::info(fmt("Send Hash case :%s",v$verdict));
                break;
        }


    }
}



event file_state_remove(f: fa_file){

       if ( !f$info?$extracted || !f$info?$sha256  )
               return;
            
       if ( f$missing_bytes > 0)
               return;
               

       #Reporter::info(fmt("UID: %s  Filenames: %s",f$conns,f$info$filename));
       local info: SandBox::Info;
       # fix it better
       for ( i in f$conns)
       {
         info$conn = f$conns[i];
         info$f = f;
       }
       info$indicator = f$info$sha256;
       info$indicator_type = get_mime(f$info$mime_type);
       info$node_name = Cluster::node;
       # add here the check for cache
       # normally check intel framework
       if ( info$indicator in distributed_cache )
       {
            Reporter::info(fmt("Cache hit for indicator %s",f$info$sha256));
            if (distributed_cache[info$indicator]$verdict == SandBox::MALICIOUS)
            {
                do_notice(info,distributed_cache[info$indicator]);
            }
            return;
       }
       Cluster::publish_hrw(Cluster::proxy_pool,f$info$sha256,send_hash_to_sandbox,info);
}

event file_sniff(f: fa_file, meta:fa_metadata){

       if ( meta?$mime_type &&  meta$mime_type in _mime_type_analysis ){
            Files::add_analyzer(f,Files::ANALYZER_SHA256);
            Files::add_analyzer(f,Files::ANALYZER_EXTRACT);

       }
}