import logging
import sys

# Global variabel för loggern
logger = None 

def setup_logger(log_file):
    # Konfigurerar logger för både fil och konsol
    global logger
    logger = logging.getLogger('IOC_Analyzer')
    logger.setLevel(logging.DEBUG)

    # Skapa formatter för loggmeddelanden
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Hanterare för fil
    try:
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except IOError as e:
        # Ger ett felmeddelande om loggfilen inte kan skapas
        print(f"[KRITISKT FEL] Kunde inte skapa eller skriva till loggfilen '{log_file}': {e}")
    
    # Hanterare för konsol
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO) # Endast INFO och högre till konsol
    console_formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

def log(message, level='INFO'):
    """En wrapper-funktion för att logga med rätt nivå."""
    global logger
    if logger is None:
        # Fallback om loggern inte initierats
        print(f"[{level}] {message}")
        return

    # Hanterar loggnivåer
    if level.upper() == 'DEBUG':
        logger.debug(message)
    elif level.upper() == 'INFO':
        logger.info(message)
    elif level.upper() == 'WARNING':
        logger.warning(message)
    elif level.upper() == 'ERROR':
        logger.error(message)
    elif level.upper() == 'CRITICAL':
        logger.critical(message)
    else:
        logger.info(message)