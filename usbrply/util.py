def add_bool_arg(parser, yes_arg, default=False, **kwargs):
    dashed = yes_arg.replace('--', '')
    dest = dashed.replace('-', '_')
    parser.add_argument(yes_arg, dest=dest, action='store_true', default=default, **kwargs)
    kwargs['help'] = 'Disable above'
    parser.add_argument('--no-' + dashed, dest=dest, action='store_false', **kwargs)
