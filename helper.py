from pathlib import Path
from shutil import copytree, copy2
import time
import logging
import hashlib

from log import CustomFormatter

simpleLogFormat = logging.Formatter('%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

fileHandler = logging.FileHandler('app.log')
fileHandler.setFormatter(simpleLogFormat)
logger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(CustomFormatter())
logger.addHandler(consoleHandler)

logger.debug('initialized')

NO_TAR = ['.zip', '.tar.gz', '.tar', '.mp4', '.mkv']


def time_me(func):
    def wrapper(*args, **kwargs):
        t1 = time.time()
        func(*args, **kwargs)
        t2 = time.time()
        logger.info('executing time: ' + str(t2-t1))
    return wrapper


# https://stackoverflow.com/questions/1131220/get-the-md5-hash-of-big-files-in-python
def find_me_sha256(path: Path) -> str:
    BLOCK_SIZE = 2**24 # TODO: arbitrary; might find a better value later 
    checksum = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            buffer = f.read(BLOCK_SIZE)
            if not buffer:
                break
            checksum.update(buffer)
    return checksum.hexdigest()


@time_me
def copy_file(src: Path, dst: Path, check_sum: bool = False, overwrite: bool = False) -> Path:
    logger.debug('copy_file(\nsrc: {}\ndst: {}\nchecksum: {}\noverwrite: {})'.format(
        str(src), 
        str(dst), 
        str(check_sum),
        str(overwrite)))
    exit_early = False

    # check if src and dst are absolute paths
    if not src.is_absolute():
        logger.warn("src directory is not an absolute path")
        exit_early = True
    if not dst.is_absolute():
        logger.warn("dst directory is not an absolute path")
        exit_early = True
    
    if exit_early:
        return None

    dst_full = dst.joinpath(src.name)
    if not dst_full.exists() or overwrite:
        try:
            copy2(src, dst_full) 
            logger.info('copied: {}'.format(str(dst_full)))
        except Exception as e:
            logger.critical(e)
            return src
    else:
        logger.warning('file already exists: {}'.format(str(dst_full)))

    if check_sum: 
        orig_hash = find_me_sha256(src)
        logger.info('hash: {}'.format(orig_hash))
        copy_hash = find_me_sha256(dst_full)

        if orig_hash == copy_hash:
            logger.info('same hash')
        else:
            # TODO: try recopying? 
            logger.warning('diff hash') 
            return src

    return None


@time_me
def copy_files(srcs: list[Path], dst: Path, src_root: Path, check_sum: bool = False, overwrite: bool = False) -> None:
    logger.debug('copy_files(\nsrc: {}\ndst: {}\nchecksum: {}\noverwrite: {})'.format(
        "\n".join(list(map(lambda x: str(x), srcs))), 
        str(dst), 
        str(src_root),
        str(overwrite)))
    exit_early = False

    def not_abs(x):
        nonlocal exit_early
        logger.warn('not absolute path: {}'.format(str(x)))
        exit_early = True

    # check if srcs and dst are absolute paths
    map(lambda x: not_abs(x) if not x.is_absolute() else logger.debug('absolute path: {}'.format(str(x))), srcs)
    if not dst.is_absolute():
        logger.warn("dst directory is not an absolute path")
        exit_early = True
    if not src_root.is_absolute():
        logger.warn("src_root directory is not an absolute path")
        exit_early = True

    if exit_early:
        return
    
    # copying individual files
    # TODO: parallelize (?)
    for src in srcs:
        logger.info('src: ' + str(src))

        # find relative path from source root directory
        try:
            rel_dir_path = src.parent.relative_to(src_root)
            logger.debug('rel_dir_path: ' + str(rel_dir_path))
        except ValueError as value_err:
            logger.critical(value_err)
            return
        
        # create new path using destination path + relative path 
        # intent: to maintain similar directory structure
        try:
            new_dst = dst.joinpath(rel_dir_path) 
            logger.info('new_dst: ' + str(new_dst))
        except Exception as e:
            logger.critical(e)
            return

        # create new parent directories if not exist already
        try:
            new_dst.mkdir(parents=True, exist_ok=False) 
            logger.info('created directory: {}'.format(str(new_dst)))
        except FileExistsError as file_exists:
            logger.debug(file_exists)
        except Exception as e:
            logger.critical(e)
            return
        
        # copy file
        try:
            bad_file = copy_file(src, new_dst, check_sum, overwrite)
        except Exception as e:
            logger.critical(e)
            return

    return 


@time_me
def copy_tree(src: Path, dst: Path) -> None:
    exit_early = False

    # check if src and dst are absolute paths
    if not src.is_absolute():
        logger.warn("src directory is not an absolute path")
        exit_early = True
    if not dst.is_absolute():
        logger.warn("dst directory is not an absolute path")
        exit_early = True

    if exit_early:
        return
    
    # copy files
    try:
        all_files = src.glob('**/*')
        copy_files(all_files, dst, src)
    except Exception as e:
        logger.critical(e)
        return
    
    return 