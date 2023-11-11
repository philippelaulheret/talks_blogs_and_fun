
static find_end_bb(ea)
{
    auto i, cur_ins, mnem;
    for (i=0; i < 0x100000; i++)
    {
        cur_ins = decode_insn(ea);
        mnem = cur_ins.mnem;
        if ((mnem == "jmp") | (mnem == "retn")) // or jz jnz ... but don;t want to deal wit hthat
        {
            return ea + cur_ins.size;
        }
        ea = ea+cur_ins.size;
    }
    return BADADDR;
}


static fix_jump_phase2(from_ea)
{
    //print("AAAA");
    auto ins = decode_insn(from_ea);
    auto jump_addr;
    
    auto func_ea = get_func_attr(from_ea, 0);
    
    auto to_ea = ins["Op0"].addr;
    
    if (1)
    //if (get_spd(from_ea) != get_spd(to_ea))
    {
        //del_stkpnt(func_ea, to_ea);
        auto parent_spd = -get_spd(from_ea);
        auto bb_spd = -get_spd(to_ea);
        
        if (from_ea == 0x0000001800364E3) {
        //if (to_ea == 0x018003AD43) { 
        print(sprintf("From: %x, to: %x", from_ea, to_ea));
        print(sprintf("Start: %x, end: %x", parent_spd, bb_spd));
        }
        auto delta = parent_spd - bb_spd;
        
        auto end_bb_ea = find_end_bb(to_ea);
        
        auto old_to_ea_spd = get_sp_delta(to_ea);
        auto old_end_bb_spd = get_sp_delta(end_bb_ea-2);
        
        if (old_to_ea_spd != 0) { print(old_to_ea_spd, to_ea); };

        auto res = add_user_stkpnt(to_ea, old_to_ea_spd  -delta );
        res = res & add_user_stkpnt(end_bb_ea-2, old_end_bb_spd + delta ); // lol sketchy but it works
        if (res ==0) { print(sprintf("error at 0x%x", to_ea)); }
    }
    return to_ea;
    
}

static clean_bb_stack(start_ea)
{
        auto end_bb_ea = find_end_bb(start_ea);
        add_user_stkpnt(start_ea, 0 );
        add_user_stkpnt(end_bb_ea-1, 0 );
        //del_stkpnt(func_ea, to_ea);
        auto parent_spd = -get_spd(end_bb_ea-1);
        auto bb_spd = -get_spd(start_ea);
        auto delta = parent_spd - bb_spd;
        add_user_stkpnt(end_bb_ea-1, 0 );
        add_user_stkpnt(end_bb_ea-1, delta );
}


// phase 1 -> make sure the basic blocks are neutral sp-wise 
//            so that a change doesn't propagate

static fix_jump_phase1(from_ea)
{
    auto ins = decode_insn(from_ea);
    auto jump_addr;
    
    auto func_ea = get_func_attr(from_ea, 0);
    
    
    // if stack changes in the bb
    auto to_ea = ins["Op0"].addr;
    auto end_bb_ea = find_end_bb(to_ea);
    
    if (1)
    //if (get_spd(to_ea) != get_spd(end_bb_ea-1))
    {
    
        add_user_stkpnt(to_ea, 0 );
        add_user_stkpnt(end_bb_ea-1, 0 );
        //del_stkpnt(func_ea, to_ea);
        auto parent_spd = -get_spd(end_bb_ea-1);
        auto bb_spd = -get_spd(to_ea);
        
        
        print(sprintf("To: %x, emd: %x", to_ea, end_bb_ea-5 ));
        print(sprintf("Start: %x, end: %x", parent_spd, bb_spd));
        
        
        
        auto delta = parent_spd - bb_spd;
        
        
        
        add_user_stkpnt(end_bb_ea-1, 0 );
        
        auto old_to_ea_spd = get_sp_delta(to_ea);
        auto old_end_bb_spd = get_spd(end_bb_ea-5);

        add_user_stkpnt(end_bb_ea-1, delta );
        //add_user_stkpnt(end_bb_ea-1, old_end_bb_spd + bb_spd ); // lol sketchy but it works
    }
    return to_ea;
    
}

static _fix_stack(ea, phase)
{

    if (phase==1)
    {
        clean_bb_stack(ea);
    }
    auto start_ea = ea;
    auto i, next_ea;
    
    next_ea = ea;
    
    auto this_func_name = get_func_name(ea);
    for ( i=0; i<10000; i++)
    {
        if (next_ea == BADADDR) break;
        next_ea = next_head(ea, BADADDR);
        auto insn = decode_insn(ea);
        auto mnem = insn.mnem;
        //print(ea);
        //print(mnem);
        
        if (phase == 0) {
        if (mnem == "pop")
        {
            add_user_stkpnt(ea + insn.size, 8);
        }
        if (mnem == "push")
        {
            add_user_stkpnt(ea + insn.size, -8);
        }
        if ((mnem == "sub") ) // sub or add targets rsp
        {
            if (insn[0].reg == 4) {
                       
                if (insn[1].type != o_imm)
                {
                    print(sprintf("%x: is not an immediate", ea));
                    if (ea == 0x18002898d )
                    {
                        print("Special case!");
                        add_user_stkpnt(ea + insn.size,  -0x1DE8);
                    }
                }
                else 
                {
                    add_user_stkpnt(ea + insn.size, - insn[1].value);
                }
            }
        }
        if ((mnem == "add") )
        {
            //https://hex-rays.com/products/ida/support/sdkdoc/group__o__.html
            if (insn[0].reg == 4) {
                if (insn[1].type != o_imm)
                {
                    print(sprintf("%x: is not an immediate", ea));
                }
                else
                {
                    add_user_stkpnt(ea + insn.size,  insn[1].value);
                }
            }
        }
        }
        if (mnem == "retn")
            { break; }
        
        if ((mnem == "jmp") || (is_cond_jump(mnem)))
            {
                if (phase == 0)
                {
                    next_ea = insn["Op0"].addr;
                }
                if (phase == 1) 
                    next_ea = fix_jump_phase1(ea); 
                if (phase == 2) 
                    next_ea = fix_jump_phase2(ea); 
            
                // if we have a normal jmp, we can keep going,
                // but with a conditional jump, need to execute both path
                if (is_cond_jump(mnem))
                {
                    // Should probably check that we're not jumping to something off
                    // like a different function
                    // but the cleanup phase from other script should have dealt with that
                    
                    auto tag = sprintf("phase %i", phase);
                    auto cmt = get_cmt(next_ea, 0);
                    if (tag == cmt)
                    {
                        print("alread visited");
                    }
                    else
                    {
                        set_cmt(next_ea, tag, 0); 
                        print("Recurisve Call");
                        print(next_ea);
                        _fix_stack(next_ea, phase);
                    }
                    next_ea = next_head(ea, BADADDR);
                }
        
        } 
            

            
        else
        {
            next_ea = next_head(ea, BADADDR);
            auto next_block_func_name = get_func_name(next_ea);
            if ((next_block_func_name == 0) || (this_func_name != next_block_func_name))
            {
                print("Done!");
                break;
            }
        }
        ea = next_ea;
    }
}


static fix_stack()
{
    _fix_stack(get_screen_ea(), 0);
    _fix_stack(get_screen_ea(), 1); // 018003CEDE   is func3
    _fix_stack(get_screen_ea(), 2);
    return 0x1800364E3; //for debug
    
}
