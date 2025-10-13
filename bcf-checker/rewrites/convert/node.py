###############################################################################
# Top contributors (to current version):
#   Leni Aniva, Haniel Barbosa, Andrew Reynolds
#
# This file is part of the cvc5 project.
#
# Copyright (c) 2009-2025 by the authors listed in the file AUTHORS
# in the top-level source directory and their institutional affiliations.
# All rights reserved.  See the file COPYING in the top-level source
# directory for licensing information.
# #############################################################################
#
# Term data structures for different kinds of terms, sorts and values in the DSL
# #

from enum import Enum, auto


class Op(Enum):

    def __new__(cls, symbol, kind):
        """
        symbol: The name of the operator in RARE
        kind: The name of the operator in BCF
        """
        entry = object.__new__(cls)
        entry._value_ = symbol
        entry.symbol = symbol
        entry.kind = kind
        return entry

    ###########################################################################
    # Arrays
    ###########################################################################
    STORE = ('store', 'BCF_UNSPEC')
    SELECT = ('select', 'BCF_UNSPEC')

    ###########################################################################
    # Bit-vectors
    ###########################################################################

    # Bit-vector predicates
    BVUGT = ('bvugt', 'bvugt')
    BVUGE = ('bvuge', 'bvuge')
    BVSGT = ('bvsgt', 'bvsgt')
    BVSGE = ('bvsge', 'bvsge')
    BVSLT = ('bvslt', 'bvslt')
    BVSLE = ('bvsle', 'bvsle')
    BVULT = ('bvult', 'bvult')
    BVULE = ('bvule', 'bvule')
    BVREDAND = ('bvredand', 'BCF_UNSPEC')
    BVREDOR = ('bvredor', 'BCF_UNSPEC')

    # Bit-vector arithmetic
    BVNEG = ('bvneg', 'bvneg')
    BVADD = ('bvadd', 'bvadd')
    BVSUB = ('bvsub', 'bvsub')
    BVMUL = ('bvmul', 'bvmul')
    BVSDIV = ('bvsdiv', 'BCF_UNSPEC')
    BVUDIV = ('bvudiv', 'BCF_UNSPEC')
    BVSREM = ('bvsrem', 'BCF_UNSPEC')
    BVUREM = ('bvurem', 'BCF_UNSPEC')
    BVSMOD = ('bvsmod', 'BCF_UNSPEC')

    # Bit-vector shifts
    BVSHL = ('bvshl', 'bvshl')
    BVLSHR = ('bvlshr', 'bvlshr')
    BVASHR = ('bvashr', 'bvashr')
    ROTATE_LEFT = ('rotate_left', 'BCF_UNSPEC')
    ROTATE_RIGHT = ('rotate_right', 'BCF_UNSPEC')

    # Bitwise bit-vector operations
    BVNOT = ('bvnot', 'bvnot')
    BVAND = ('bvand', 'bvand')
    BVOR = ('bvor', 'bvor')
    BVXOR = ('bvxor', 'bvxor')
    BVNAND = ('bvnand', 'BCF_UNSPEC')
    BVNOR = ('bvnor', 'BCF_UNSPEC')
    BVXNOR = ('bvxnor', 'BCF_UNSPEC')
    BVUADDO = ('bvuaddo', 'BCF_UNSPEC')
    BVSADDO = ('bvsaddo', 'BCF_UNSPEC')
    BVUMULO = ('bvumulo', 'BCF_UNSPEC')
    BVSMULO = ('bvsmulo', 'BCF_UNSPEC')
    BVUSUBO = ('bvusubo', 'BCF_UNSPEC')
    BVSSUBO = ('bvssubo', 'BCF_UNSPEC')
    BVSDIVO = ('bvsdivo', 'BCF_UNSPEC')
    BVNEGO = ('bvnego', 'BCF_UNSPEC')

    BVITE = ('bvite', 'bvite')
    BVCOMP = ('bvcomp', 'BCF_UNSPEC')

    ZERO_EXTEND = ('zero_extend', 'zero_extend')
    SIGN_EXTEND = ('sign_extend', 'sign_extend')
    CONCAT = ('concat', 'concat')
    EXTRACT = ('extract', 'extract')
    REPEAT = ('repeat', 'repeat')

    BVSIZE = ('@bvsize', 'bvsize')
    BVCONST = ('@bv', 'bv_sym_val')
    BVMAX = ('@bvmax', 'bvmax')

    ###########################################################################
    # Boolean
    ###########################################################################

    NOT = ('not', 'not')
    AND = ('and', 'conj')
    OR = ('or', 'disj')
    IMPLIES = ('=>', 'implies')
    XOR = ('xor', 'xor')

    ###########################################################################
    # Arithmetic
    ###########################################################################

    NEG = ('neg', 'bvneg')  # This is parsed with SUB, so the key is None
    ADD = ('+', 'bvadd')
    SUB = ('-', 'bvsub')
    MULT = ('*', 'bvmul')
    INT_DIV = ('div', 'BCF_UNSPEC')
    INT_DIV_TOTAL = ('div_total', 'BCF_UNSPEC')
    DIV = ('/', 'BCF_UNSPEC')
    DIV_TOTAL = ('/_total', 'BCF_UNSPEC')
    MOD = ('mod', 'BCF_UNSPEC')
    MOD_TOTAL = ('mod_total', 'BCF_UNSPEC')
    ABS = ('abs', 'BCF_UNSPEC')
    LT = ('<', 'bvslt')
    GT = ('>', 'bvsgt')
    LEQ = ('<=', 'bvsle')
    GEQ = ('>=', 'bvsge')
    POW2 = ('int.pow2', 'BCF_UNSPEC')
    TO_INT = ('to_int', 'BCF_UNSPEC')
    TO_REAL = ('to_real', 'BCF_UNSPEC')
    IS_INT = ('is_int', 'BCF_UNSPEC')
    DIVISIBLE = ('divisible', 'BCF_UNSPEC')

    INT_ISPOW2 = ('int.ispow2', 'BCF_UNSPEC')  # Backdoor for some bv rewrites
    INT_LENGTH = ('int.log2', 'BCF_UNSPEC')  # Backdoor for some bv rewrites

    ###########################################################################
    # Theory-independent
    ###########################################################################

    EQ = ('=', 'eq')
    ITE = ('ite', 'ite')
    # Lambda is not an operator. It exists here as a backdoor to simplify
    # parsing logic.
    LAMBDA = ('lambda', 'BCF_UNSPEC')
    BOUND_VARS = ('bound_vars', 'BCF_UNSPEC')
    DISTINCT = ('distinct', 'neq')

    UBV_TO_INT = ('ubv_to_int', 'BCF_UNSPEC')
    SBV_TO_INT = ('sbv_to_int', 'BCF_UNSPEC')
    INT_TO_BV = ('int_to_bv', 'BCF_UNSPEC')

    TYPE_OF = ('@type_of', 'BCF_UNSPEC')


class BaseSort(Enum):
    Bool = auto()
    BitVec = auto()
    Int = auto()
    Real = auto()
    AbsBitVec = auto()
    AbsAbs = auto()


class Node:

    def __init__(self, children, sort=None):
        assert all(isinstance(child, Node) for child in children)
        self.children = children
        self.sort = sort
        self.name = None

    def __getitem__(self, i):
        return self.children[i]

    def __eq__(self, other):
        if len(self.children) != len(other.children):
            return False

        for c1, c2 in zip(self.children, other.children):
            if c1 != c2:
                return False

        return True


class Sort(Node):

    def __init__(self, base, args=None, is_list=False, is_const=False):
        super().__init__(args if args else [])
        self.base = base
        self.is_list = is_list
        self.is_const = is_const

    def __eq__(self, other):
        return self.base == other.base and self.is_list == other.is_list and\
            super().__eq__(other)

    def __hash__(self):
        return hash((self.base, self.is_list, tuple(self.children)))

    def __repr__(self):
        rep = ''
        if len(self.children) == 0:
            rep = '{}'.format(self.base)
        else:
            rep = '({} {})'.format(
                self.base, ' '.join(str(child) for child in self.children))
        if self.is_list:
            rep = rep + ' :list'
        return rep

    def is_int(self):
        return self.base == BaseSort.Int


class Placeholder(Node):

    def __init__(self):
        super().__init__([], None)

    def __eq__(self, other):
        return isinstance(other, Placeholder)

    def __hash__(self):
        return hash('_')

    def __repr__(self):
        return '_'


class Var(Node):

    def __init__(self, name, sort=None):
        super().__init__([], sort)
        self.name = name

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def __repr__(self):
        return self.name


class CBool(Node):

    def __init__(self, val):
        super().__init__([])
        self.val = val

    def __eq__(self, other):
        assert isinstance(other, Node)
        return isinstance(other, CBool) and self.val == other.val

    def __hash__(self):
        return hash(self.val)

    def __repr__(self):
        return str(self.val)


class CInt(Node):

    def __init__(self, val):
        super().__init__([])
        self.val = val

    def __eq__(self, other):
        return isinstance(other, CInt) and self.val == other.val

    def __hash__(self):
        return hash(self.val)

    def __repr__(self):
        return str(self.val)


class CRational(Node):

    def __init__(self, val):
        super().__init__([])
        self.val = val

    def __eq__(self, other):
        return isinstance(other, CRational) and self.val == other.val

    def __hash__(self):
        return hash(self.val)

    def __repr__(self):
        return str(self.val)


class CString(Node):

    def __init__(self, val):
        super().__init__([])
        self.val = val

    def __eq__(self, other):
        return self.val == other.val

    def __hash__(self):
        return hash(self.val)

    def __repr__(self):
        return f'"{self.val}"'


class App(Node):

    def __init__(self, op, args):
        super().__init__(args)
        self.op = op

    def __eq__(self, other):
        return isinstance(
            other, App) and self.op == other.op and super().__eq__(other)

    def __hash__(self):
        return hash((self.op, tuple(self.children)))

    def __repr__(self):
        return '({} {})'.format(
            self.op, ' '.join(str(child) for child in self.children))
