import asyncio
import threading

from gv_tui import GalleryVaultTUI


class DummyBuffer:
    cursor_position = 0


class DummyArea:
    text = ""
    buffer = DummyBuffer()


class DummyApplication:
    invalidations = 0

    def invalidate(self):
        self.invalidations += 1


def test_worker_log_is_scheduled_on_the_ui_loop():
    async def scenario():
        tui = GalleryVaultTUI.__new__(GalleryVaultTUI)
        tui._loop = asyncio.get_running_loop()
        tui.log_area = DummyArea()
        tui.app = DummyApplication()

        worker = threading.Thread(target=tui.log, args=("from worker",))
        worker.start()
        worker.join()
        await asyncio.sleep(0)

        assert "from worker" in tui.log_area.text
        assert tui.app.invalidations == 1

    asyncio.run(scenario())
