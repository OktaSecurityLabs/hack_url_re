import os
import json
import time
import re
import argparse
import enum
from sys import argv, stderr, stdin
from multiprocessing import Queue, Process
from multiprocessing.queues import Empty
from pathlib import Path
from enum import Enum

import z3
import ply.lex
import toolz

from .solving import get_warnings
from .parsing import RegexParser, GROUP, character_classes

from . import ui

inputs = Queue()
outputs = Queue()

def process_template(ex):
    m = re.search(r'\${(.*)}', ex)
    if m:
        if '==' in m.group(1):
            # don't deal with these
            return None
        else:
            return re.sub(r'\${.*?}', 'x', ex)

    else:
        return ex


def process_dash(ex):
    def _process(ss):
        if ss.endswith('|'):
            return r'\-'
        elif any(ss.endswith('\\' + cc) for cc in character_classes):
            return r'\-'
        else:
            return '-'

    split = ex.split('-')
    return ''.join(ss + _process(ss) for ss in split[:-1]) + split[-1]


def process_bar_rparen(ex):
    def _process(ss):
        if ss.endswith('\\'):
            return r'\|)'
        else:
            return ')?'

    split = ex.split('|)')
    return ''.join(ss + _process(ss) for ss in split[:-1]) + split[-1]


def process_outer_group(ex):
    if ex.startswith('(?:)'):
        ex = ex[4:]

    if ex.endswith('(?:$|)'):
        ex = ex[:-len('(?:$|)')]
    elif ex.endswith('(?:|$)'):
        ex = ex[:-len('(?:|$)')]
    elif ex.endswith('(?:|/)'):
        ex = ex[:-len('(?:|/)')]


    print('parsing ', ex, end=' ')
    parsed = RegexParser().parse(ex)
    print('done parsing ', ex)

    if (parsed is not None and parsed['root'] is not None
        and parsed['root'][0] == GROUP):
        m = re.match(r'^\(.*\)$', ex)

        if m:
            if ex.startswith('(?:'):
                return ex[3:-1]
            else:
                return ex[1:-1]


    return ex


def process_lookahead(ex):
    if ex.startswith('^(?!.*so=wlp)'):
        return '^' + ex[len('^(?!.*so=wlp)'):]
    else:
        return ex


def work(worker_id, inputs: Queue, outputs: Queue, quick: bool, require_literal_dot_in_domain: bool):

    def _callback(length, result, answer):
        if result == z3.sat:
            print('worker {}'.format(worker_id), length, result, answer)
        else:
            print('worker {}'.format(worker_id), length, result)

    while not inputs.empty():
        try:
            appId, ex = inputs.get_nowait()
        except Empty:
            time.sleep(2)
            break

        ex2 = process_template(ex)
        if ex2 == None:
            outputs.put((appId, [], True, ['Unable to parse']))
            continue

        #ex3 = process_outer_group(process_bar_rparen(process_dash(process_lookahead(ex2))))
        ex3 = process_bar_rparen(process_dash(process_lookahead(ex2)))

        #if ex2 != ex3:
        #    print('removed outer group', appId, ex2, '->', ex3)
        #continue


        _my_parser = RegexParser()
        def just_parse(solver, regex):
            # TODO: enable this as a strategy, move to ui.py
            # just check parsing
            parsed = _my_parser.parse(regex)
            parse_result = 'OK' if not parsed['errors'] else 'error'

            return (z3.unknown, {"parse_result": parse_result, "witness": [repr(x) for x in parsed['errors']]})


        try:
            result, evidence = ui.solve(ex3, quick=quick, require_literal_dot_in_domain=require_literal_dot_in_domain)
        except ply.lex.LexError:
            print('Lex error on ', ex3)
            lex_errors.append(ex3)
            continue
        except ValueError as err:
            outputs.put((appId, [], True, [repr(err)]))
            continue
        else:
            _warnings = get_warnings(ex)
            outputs.put((appId, result, evidence, _warnings))


lex_errors = []
undecided = []
found_domains = {}
witnesses = {}
warnings = {}

results = {}

def process_outputs(outputs: Queue):
    # print(ex)

    try:
        appId, result, witness, _warnings = outputs.get_nowait()
    except Empty:
        time.sleep(2)
        return

    witnesses[appId] = witness
    warnings[appId] = _warnings

    results[appId] = result

    print('witness:'.format(witness))
    print('unknown?', result == z3.unknown)

    return appId


class Verdict(Enum):
    undecided = enum.auto()
    warning = enum.auto()
    ok = enum.auto()
    bad = enum.auto()


output_dir = Path('output')
sentinel_path = output_dir.joinpath('.sentinel_28974659')

paths = {
    Verdict.bad: output_dir.joinpath('badpatterns.txt'),
    Verdict.ok: output_dir.joinpath('okpatterns.txt'),
    Verdict.undecided: output_dir.joinpath('undecided_patterns.txt'),
    Verdict.warning: output_dir.joinpath('warning_patterns.txt'),
    }


def run_solvers(json_path: Path, num_processes: int, quick: bool, require_literal_dot_in_domain: bool,
                force_output: bool):
    if (not force_output
        and output_dir.exists()
        and not sentinel_path.exists()):

        stderr.write('It appears the ./output directory was not created by me. Rerun with -f continue anyway.\n')
        exit(1)

    output_dir.mkdir(exist_ok=True)
    sentinel_path.touch(exist_ok=True)


    if paths[Verdict.bad].exists():
        # Use previous results.
        examined = set(toolz.concat(
            [(line.strip().split(' ')[0])
            for line in pp.read_text().strip().split('\n')
            if line.strip() != '']
            for pp in paths.values()))

        out_mode = 'a'
    else:
        examined = set()
        out_mode = 'w'


    if json_path.exists():
        with json_path.open() as fp:
            regexes = json.load(fp)
    else:
        stderr.write('Specify a json file\n')
        exit(1)


    num_regexes = len(regexes) - len(examined)
    for appId, ex in regexes.items():
        #assert ex == ex.strip()
        if appId not in examined:
            ex = ex.lstrip()
            inputs.put([appId, ex])


    processes = []


    for ii in range(num_processes):
        pp = Process(target=work, args=(ii, inputs, outputs, quick, require_literal_dot_in_domain))
        processes.append(pp)

        pp.start()


    with paths[Verdict.bad].open(out_mode) as bad, \
        paths[Verdict.ok].open(out_mode) as ok, \
        paths[Verdict.warning].open(out_mode) as warnings_f, \
        paths[Verdict.undecided].open(out_mode) as unknowns_f:

        cnt = 0
        while cnt < num_regexes:
            appId = process_outputs(outputs)
            if appId:
                if results[appId] == z3.sat:
                    bad.write('{} {} {}\n'.format(appId, regexes[appId], json.dumps(witnesses[appId], ensure_ascii=False)))
                    bad.flush()
                elif results[appId] == z3.unknown:
                    unknowns_f.write('{} {} {}\n'.format(appId, regexes[appId], json.dumps(witnesses[appId], ensure_ascii=False)))
                    unknowns_f.flush()
                else:
                    ok.write('{} {} {}\n'.format(appId, regexes[appId], json.dumps(witnesses[appId], ensure_ascii=False)))
                    ok.flush()

                if warnings[appId]:
                    warnings_f.write('{} {} {}\n'.format(appId, regexes[appId], warnings[appId]))
                    warnings_f.flush()

                cnt += 1

    for pp in processes:
        pp.join()


def main():
    parser = argparse.ArgumentParser(
        description="""
        Reads a regexes from a JSON file and attempts to hack them.
        The JSON must be a dictionary, with the regexes as values. The keys are meant
        for identification purposes in the output. For example:

            `{1: "http://example.com",
             "x": "http://example2.com"}`

        Note that if old output exists in the output directory, I will pick up where I left off.
        """
    )

    parser.add_argument('--quick', '-q', action='store_true',
                        help='''Applies a quick attack.  Otherwise applies a comprehensive attack,
                        which will find everything that the quick attack does.''')

    parser.add_argument('--num-processes', default=1, metavar='N', type=int,
                        help='''Number of processes.''')

    parser.add_argument('file', metavar='F', type=Path, nargs=1,
                        help='''JSON file containing a dictionary whose values are regexes.''')

    parser.add_argument('--require-literal-dot-in-domain', action='store_true',
                        help='''Require at least one dot in the domain name.''')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='''Enable verbose logging.''')

    parser.add_argument('--force', '-f', action='store_true',
                        help='''Force clobbering of output directory.''')


    args = parser.parse_args()

    if args.verbose:
        ui.set_verbose()

    run_solvers(json_path=args.file[0],
                num_processes=args.num_processes,
                quick=args.quick,
                require_literal_dot_in_domain=args.require_literal_dot_in_domain,
                force_output=args.force)
