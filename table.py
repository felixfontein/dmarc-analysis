def format_table(table, mode='text', padding=1, max_cell_width=None):
    """Pretty-prints table.

    A `None` entry is interpreted as a horizontal line. Multiple `None` entries
    are combined to one fat horizontal line. Table rows should tuples or lists,
    where every entry is converted to a string (`None` is interpreted as an
    empty string) before outputting. An entry can also be a tuple, in which
    case the first part of the tuple is interpreted as the content and the
    second as a cell color.

    The result is returned as a string, which can be fed to `print` or written
    to a file.

    `mode` can be 'text' or 'pretty_text' at the moment. 'text' uses ASCII
    characters for formatting, while 'pretty_text' uses Unicode box-drawing
    characters. Both 'text' and 'pretty_text' support three colors: 'red',
    'green' and 'yellow'. They are output using ANSI color codes.
    """

    def format_table_text(table, repertoire):
        def make_line(columns, repertoire):
            line = repertoire[0]
            for i, c in enumerate(columns):
                line += repertoire[3] * (c + 2 * padding)
                line += repertoire[1 if i + 1 < len(columns) else 2]
            return line

        def colorize(text, color_id):
            return '\x1b[{0}m{1}\x1b[0m'.format(color_id, text)

        columns = []
        output_table = []
        last_was_none = False
        DOUBLE = (None, )
        for row in table:
            if row is not None:
                last_was_none = False
                nr = []
                if len(columns) < len(row):
                    columns += [0] * (len(row) - len(columns))
                for i, c in enumerate(row):
                    color = None
                    if c is None:
                        c = ''
                    elif isinstance(c, tuple):
                        if len(c) > 1:
                            color = c[1]
                        c = c[0]
                    c = str(c)
                    columns[i] = max(columns[i], len(c))
                    nr.append((c, color))
                output_table.append(nr)
            else:
                if last_was_none:
                    output_table[-1] = DOUBLE
                else:
                    output_table.append(None)
                last_was_none = True
        if max_cell_width is not None:
            if isinstance(max_cell_width, (tuple, list)):
                for i in range(max(len(columns), len(max_cell_width))):
                    if max_cell_width[i] is not None:
                        columns[i] = min(columns[i], max_cell_width[i])
            else:
                for i in range(len(columns)):
                    columns[i] = min(columns[i], max_cell_width)
        output = []
        for i, row in enumerate(output_table):
            li = 3 + (0 if i == 0 else 2 if i + 1 == len(output_table) else 1) * 8
            if row is None:
                line = make_line(columns, repertoire[li:li + 4])
            elif row is DOUBLE:
                line = make_line(columns, repertoire[li + 4:li + 8])
            else:
                line = repertoire[0]
                if len(row) < len(columns):
                    row += [('', None)] * (len(columns) - len(row))
                for j, (w, (text, col)) in enumerate(zip(columns, row)):
                    c = text
                    if len(c) > columns[j]:
                        c = c[:columns[j]]
                    if col is not None:
                        if col == 'green':
                            c = colorize(c, 32)
                        elif col == 'red':
                            c = colorize(c, 31)
                        elif col == 'yellow':
                            c = colorize(c, 33)
                        else:
                            print("Unknown color '{0}'!".format(col))
                    line += ' ' * padding + c + (' ' * (w - len(text))) + ' ' * padding + repertoire[1 if j + 1 < len(columns) else 2]
            output.append(line)
        return '\n'.join(output)

    if mode == 'text':
        return format_table_text(table, '|||' '+++-' '+++=' '+++-' '+++=' '+++-' '+++=')
    elif mode == 'pretty_text':
        return format_table_text(table, '\u2503\u2502\u2503' '\u250e\u252c\u2512\u2500' '\u250f\u252f\u2513\u2501' '\u2520\u253c\u2528\u2500' '\u2523\u253f\u252b\u2501' '\u2516\u2534\u251a\u2500' '\u2517\u2537\u251b\u2501')
    else:
        raise Exception("Unknown table mode '{0}'!".format(mode))
