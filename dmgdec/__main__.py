from typing import BinaryIO

import click
from tqdm import trange

from dmgdec import DMG, __version__


@click.command()
@click.version_option(message=f'dmgdec {__version__}')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input DMG file.',
    required=True,
)
@click.option(
    '-k',
    '--key',
    'key',
    type=str,
    help='Decryption key.',
    required=True,
)
@click.option(
    '-o',
    '--output',
    'output',
    type=click.File('wb'),
    help='Output DMG file.',
    required=True,
)
def main(input_: BinaryIO, key: str, output: BinaryIO) -> None:
    """A Python CLI tool for decrypting IPSW DMGs."""

    click.echo(f'Reading {input_.name}...')

    dmg = DMG(fd=input_)
    dmg.key = bytes.fromhex(key)

    click.echo(f'Outputting to {output.name}...')
    for block in trange(dmg.nrblocks):
        output.write(dmg.read_block(block))

    click.echo('Done!')


if __name__ == '__main__':
    main()
