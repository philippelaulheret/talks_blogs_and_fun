static find_end_bb(ea)
{
   /* if (!is_code(ea) )
    {
        print("NOTTTT CODE!!!");
    }*/
    auto i, cur_ins, mnem;
    for (i=0; i < 0x100000; i++)
    {
        
        cur_ins = decode_insn(ea);
        mnem = cur_ins.mnem;
        //if (ea == 0x180033244 ) print(mnem);
        if ((mnem == "jmp") | (mnem == "retn")) // or jz jnz ... but don;t want to deal wit hthat
        {
            return ea + cur_ins.size;
        }
        ea = ea+cur_ins.size; // next_head(ea, BADADDR); // instructions aren't mark as code
                                                        // next_head shits the bed
    }
    return BADADDR;
}

static fixup_stack(start_ea, end_ea, parent_ea)
{
    auto func_ea = get_func_attr(start_ea, 0);
    
    /*
    if (get_spd(parent_ea) != get_spd(start_ea))
    {
        auto parent_spd = -get_spd(parent_ea);
        auto bb_spd = -get_spd(start_ea);
        print(sprintf("Start: %x, end: %x parent: %x", start_ea, end_ea, parent_ea));
        print(sprintf("Start: %x, parent: %x", bb_spd, parent_spd));
        if (get_sp_delta(start_ea) != 0)
        {
            print("!!!!!!!!!!!!!!!");
        }
        add_user_stkpnt(start_ea,  -parent_spd + bb_spd + get_sp_delta(start_ea));
        print(sprintf("NEW -> Start: %x, parent: %x", -get_spd(start_ea), -get_spd(parent_ea)));
        
    }
    */
    auto ea;
    ea = start_ea;
    while (ea < end_ea)
    {
        //del_stkpnt(func_ea, ea);
        auto cur_insn = decode_insn(ea);
        
        if (cur_insn.mnem == "call")
        {
            auto call_addr = cur_insn[0].addr;
            if (get_func_name(call_addr) == "resolve_and_invoke")
            {
                print("AAAA");
                print(ea);
                add_user_stkpnt(ea+5, -0x20);
                //add_auto_stkpnt(func_ea, next_head(ea+5, BADADDR), 0);
                //add_user_stkpnt(next_head(ea+5, BADADDR), 0);
            }
        }
        ea = next_head(ea, BADADDR);
    }
}

static process_jump(ea)
{
    
    auto cur_ins;
    auto next_ea, end_bb; 
    cur_ins = decode_insn(ea);
    next_ea = cur_ins["Op0"].addr;
    end_bb = find_end_bb(next_ea);
    
    //print(sprintf("Jump at %x, to %x, until %x", ea, next_ea, end_bb));
    if (get_func_name(next_ea) != 0)
    {
        if (get_func_name(next_ea) == get_func_name(ea))
        {
            print("Block already in function");
            //return next_ea;
           
        }
        else 
        {
            print(sprintf("%x !!!  Block belong to other function", ea));
            //return BADADDR;
            del_func(next_ea);
            append_func_tail(ea, next_ea, end_bb);
        }
    }
    else
    {
        auto res = append_func_tail(ea, next_ea, end_bb);
        if (res == 0) { 
            print(sprintf("0x%x append function_tail failed", ea)); 
            print(sprintf("next:0x%x end:0x%x", next_ea, end_bb)); 
            res = append_func_tail(ea, next_ea, find_end_bb(next_ea));
            if (res == 0) print("Failed Twice");
        }
    }
    
    fixup_stack(next_ea, end_bb, ea);
    return next_ea;
    
}

static is_cond_jump(mnem)
{
    if (mnem == "jz") return 1;
    if (mnem == "jnz") return 1;
    if (mnem == "jb") return 1;
    if (mnem == "jnb") return 1;
    if (mnem == "js") return 1;
    if (mnem == "jns") return 1;
    if (mnem == "jg") return 1;
    if (mnem == "jge") return 1;
    if (mnem == "jbe") return 1;
    if (mnem == "jse") return 1;
    if (mnem == "jl") return 1;
    if (mnem == "jle") return 1;
    if (mnem == "jls") return 1;
    return 0;
}

static _fixup(start_ea)
{
    auto ea, next_ea, i;
    //start_ea = 0x18003E0D5;
    ea = start_ea;
    
    auto max_retry = 100;
    auto ignore_retry_until_first_undefined = 1;
    auto this_func_name = get_func_name(start_ea);
    for ( i=0; i<200000; i++)
    {

        if (next_ea == BADADDR) break;
        
        next_ea = ea + decode_insn(ea).size;
        //next_ea = next_head(ea, BADADDR);
        print(sprintf("next_ea: %x", next_ea));
        auto mnem = decode_insn(ea).mnem;
        if (mnem == "jmp")
            { 
                if (get_func_name(ea) != 0)
                {
                    if (!ignore_retry_until_first_undefined)
                        max_retry = max_retry -1 ;
                    if (max_retry < 0)
                    {
                        print("probably looped");
                        print(ea);
                        next_ea = BADADDR;
                        break;
                    }
                }
                else
                {
                    ignore_retry_until_first_undefined = 0;
                }
                next_ea = process_jump(ea); 
                ea = next_ea;
            }
        else
        {
            if (mnem != "mov") 
                { 
                //print(mnem); 
                }
            if (is_cond_jump(mnem) && 1) //let's avoid this for now
            {
                auto jump_addr;
                jump_addr =  decode_insn(ea)["Op0"].addr;
                
                // check if the target block already belong
                // to the function
                // mostly trying to avoid infinite loops....
                if (get_func_name(jump_addr) == 0) // || get_func_name(jump_addr) != this_func_name
                {
                    process_jump(ea); // will add the jumped bb to function
                    _fixup(jump_addr); // recurcsively process that
                }
            }
            if (mnem == "retn")
            {
                print("retn found");
                break;
            }
        }
        ea = next_ea;
    }
}

//warning, it may/will infinite loop and may have to be run a few times in different location within a function
static fixup()
{
    _fixup(get_screen_ea());
}
