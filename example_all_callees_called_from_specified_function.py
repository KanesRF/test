def find_all_callees(start_ea):
    '''Return a set of all callees called from the specified function.'''
    
    callees = {}
    visited = set([])
    pending = set([start_ea])
    
    while len(pending) > 0:
        start_ea = pending.pop()

        fname = GetFunctionName(start_ea)
        if not fname: continue

        callees[start_ea] = fname
        visited.add(start_ea)
        
        end_ea = FindFuncEnd(start_ea)
        if end_ea == BADADDR: continue

        all_refs = set([])
        # For each defined element in the function.
        for head in Heads(start_ea, end_ea):
            # We are only interested in code
            if not isCode(GetFlags(head)): continue

            # Get the references made from the current instruction and keep only the ones 
            # not local to the function. Assume all such references are function calls.
            refs = CodeRefsFrom(head, 0)
            refs = set(filter(lambda x: not (x>=start_ea and x<=end_ea), refs))
            all_refs |= refs

        all_refs -= visited
        pending |= all_refs

    return callees

# main
ea = ScreenEA()
callees = find_all_callees(ea)
print '0x%08X: %s callees:' % (ea, callees[ea])
for ea in callees:
    print '    0x%08X: %s' % (ea, callees[ea])