import pytest

from utils.config import ATTACK_TYPES, CLASS_LABELS
from utils.helpers import get_class_label


def test_class_labels_are_consistent():
    assert CLASS_LABELS[0] == "Benign"
    assert CLASS_LABELS[1] == "DoS"
    assert CLASS_LABELS[2] == "DDoS"
    assert CLASS_LABELS[3] == "PortScan"
    assert CLASS_LABELS[4] == "BruteForce"
    assert CLASS_LABELS[5] == "Botnet"
    assert CLASS_LABELS[6] == "WebAttack"
    assert CLASS_LABELS[7] == "Infiltration"

    assert get_class_label(1) == "DoS"
    assert get_class_label(6) == "WebAttack"
    assert get_class_label(10) == "PortScan"
    assert get_class_label(11) == "BruteForce"


def test_attack_type_normalization_handles_dataset_labels():
    # The training loader needs pandas, which the Pi's slim
    # requirements-pi.txt leaves out; skip there instead of failing collection.
    pytest.importorskip("pandas")
    from training.dataset_loader import CICIDSDatasetLoader

    loader = CICIDSDatasetLoader()

    assert loader.get_label("BENIGN") == 0
    assert loader.get_label("DoS Hulk") == 1
    assert loader.get_label("PORTSCAN") == 3
    assert loader.get_label("SSH-Patator") == 4
    assert loader.get_label("Web Attack – XSS") == 6
    assert loader.get_label("Infiltration") == 7
    assert ATTACK_TYPES.get("PortScan") == 3
