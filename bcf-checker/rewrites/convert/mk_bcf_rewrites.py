import argparse
from rw_parser import Parser
from node import *
from util import *


def to_bcf_ty(sort):
    if sort.base == BaseSort.Bool:
        bcf_ty = 'Bool'
    elif sort.base == BaseSort.Int:
        bcf_ty = 'Int' # BV(32)
    elif sort.base == BaseSort.AbsBitVec:
        bcf_ty = 'BVQ'  # bv with arbitrary width
    elif sort.base == BaseSort.AbsAbs:
        bcf_ty = 'Q'
    elif sort.base == BaseSort.BitVec:
        assert len(sort.children) == 1, \
            "BitVec parser generated an incorrect number of children"
        bcf_ty = f'BV({sort.children[0]})'
    else:
        die(f'Unsupported sort: {sort}')

    if sort.is_list:
        bcf_ty += 's'
    return bcf_ty


def to_bcf_const(expr):
    if isinstance(expr, CBool):
        return '_TRUE' if expr.val else '_FALSE'
    elif isinstance(expr, CInt):
        # dump the int into a list of u32 hex values
        val = expr.val
        hex_list = []
        if val == 0:
            hex_list.append('0')
        elif val > 0:
            while val > 0:
                hex_list.append(hex(val & 0xffffffff))
                val >>= 32
    if len(hex_list) != 0:
        return f'bv_val(32, {", ".join(hex_list)})'

    die(f'Cannot generate constant for {expr}')


def to_bcf_op(op):
    return op.kind if op.kind != 'BCF_UNSPEC' else None


def dump_expr(expr, var_position):
    if isinstance(expr, App):
        op = to_bcf_op(expr.op)
        if op is None:
            return None
        children = []
        for ch in expr.children:
            child = dump_expr(ch, var_position)
            if child is None:
                return None
            children.append(child)
        return f'{op}({", ".join(children)})'
    elif isinstance(expr, Var):
        return f'V({var_position[expr.name]})'
    elif isinstance(expr, CBool) or isinstance(expr, CInt):
        return to_bcf_const(expr)
    else:
        die(f'Cannot generate expression for {expr}')


def is_true_cond(cond):
    return isinstance(cond, CBool) and cond.val


def dump_rule(rule):
    name = rule.get_enum()
    if rule.is_fixed_point:
        # print to stderr
        print("// skipping fixed point rule:", rule.name, file=sys.stderr)
        return None, False

    var_tys = []
    var_names = []
    for var in rule.bvars:
        var_tys.append(to_bcf_ty(var.sort))
        var_names.append(var.name)
    var_position = {var_name: i for i, var_name in enumerate(var_names)}

    cond = "" if rule.cond is None or is_true_cond(rule.cond) else dump_expr(rule.cond, var_position)
    match = dump_expr(rule.lhs, var_position)
    target = dump_expr(rule.rhs, var_position)
    if cond is None or match is None or target is None:
        print(f"// skipping rule with unsupported op: {rule.name} ", file=sys.stderr)
        return None, False

    if cond == "":
        return f"({name}, ({', '.join(var_tys)}), {match}, {target})", False
    else:
        return f"({name}, ({', '.join(var_tys)}), {cond}, {match}, {target})", True


def dump_bcf_rewrites(rewrite_file, enum_variants, cond_bcf_rules, bcf_rules):
    parser = Parser()
    with open(rewrite_file, 'r') as f:
        rules = parser.parse_rules(f.read())
    for rule in rules:
        bcf_rule, is_cond_rule = dump_rule(rule)
        if bcf_rule is None:
            continue
        if is_cond_rule:
            cond_bcf_rules.append(bcf_rule)
        else:
            bcf_rules.append(bcf_rule)
        enum_variants.append(rule.get_enum())


def main():
    parser = argparse.ArgumentParser(description="Compile rewrite rules.")
    parser.add_argument("--rewrites_file",
                                nargs='+',
                                type=str,
                                help="Rule files")
    parser.add_argument("--no-macro", action="store_true",
                        help="Do not use macro for rules")
    parser.add_argument("--no-enum-variants", action="store_true",
                        help="Do not print enum variants")
    args = parser.parse_args()
    enum_variants = []
    cond_bcf_rules = []
    bcf_rules = []
    for rewrite_file in args.rewrites_file:
        dump_bcf_rewrites(rewrite_file, enum_variants, cond_bcf_rules, bcf_rules)

    if len(bcf_rules) != 0:
        print("// Rewrite Rules from: {}".format(args.rewrites_file))
        for rule in bcf_rules:
            if args.no_macro:
                print(rule)
            else:
                print(f"REWRITE{rule};")

    if len(cond_bcf_rules) != 0:
        print("// Conditional Rewrite Rules from: {}".format(args.rewrites_file))
        for rule in cond_bcf_rules:
            if args.no_macro:
                    print(rule)
            else:
                print(f"REWRITE_COND{rule};")

    if len(enum_variants) != 0 and not args.no_enum_variants:
        print()
        print(',\n'.join(enum_variants))


if __name__ == "__main__":
    main()
