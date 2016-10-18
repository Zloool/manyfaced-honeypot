import os
import runme
import settings
import shutil


def test_create_file():
    test_msg = "test"
    test_dir = "test"
    assert runme.create_file(test_msg, test_dir) is None
    assert os.path.exists("{0}{1}".format(settings.HONEYFOLDER, test_dir))
    testfile = "{0}{1}/{2}".format(
        settings.HONEYFOLDER,
        test_dir,
        os.listdir(
            settings.HONEYFOLDER +
            test_dir)[0],
        )
    assert os.path.exists(testfile)
    with open(testfile, "r") as f:
        assert f.read() == test_msg
        f.close()
    shutil.rmtree(settings.HONEYFOLDER+test_dir)
