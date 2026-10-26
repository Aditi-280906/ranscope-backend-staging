
"""Aggregate observed RANSCOPE Android events into model features.

Only features supported by the current Frida hooks are populated.
Unobservable features remain unavailable; they are never fabricated as zero.
"""

from collections import Counter
from pathlib import PurePosixPath
from threading import Lock
from typing import Any


REQUIRED_FEATURES = [
    "CAIT_camera_id_list_count",
    "CAIT_camera_open_count",
    "EAP_cipher_doFinal_count",
    "MPVG_checkSelfPermission_count",
    "MPVG_requestPermissions_count",
    "SFIM_file_delete_count",
    "SFIM_file_read_open_count",
    "SFIM_file_rename_count",
    "SFIM_file_write_open_count",
    "avg_depth",
    "avg_entropy",
    "close_write_count",
    "create_count",
    "csv_count",
    "delete_count",
    "docx_count",
    "entropy_observation_count",
    "file_event_count",
    "jpg_count",
    "json_count",
    "log_count",
    "max_entropy",
    "md_count",
    "modify_count",
    "moved_from_count",
    "moved_to_count",
    "pdf_count",
    "png_count",
    "txt_count",
    "unique_path_count",
]

# These metrics are not directly available from the current hooks.
UNAVAILABLE_FEATURES = {
    "avg_entropy",
    "max_entropy",
    "entropy_observation_count",
    "close_write_count",
    "create_count",
    "modify_count",
    "moved_from_count",
    "moved_to_count",
}

EXTENSION_FEATURES = {
    ".csv": "csv_count",
    ".docx": "docx_count",
    ".jpg": "jpg_count",
    ".jpeg": "jpg_count",
    ".json": "json_count",
    ".log": "log_count",
    ".md": "md_count",
    ".pdf": "pdf_count",
    ".png": "png_count",
    ".txt": "txt_count",
}

PATH_EVENTS = {
    "file_read_open",
    "file_write_open",
    "file_delete",
    "file_rename",
}


class AndroidEventAggregator:
    """Accumulate observed Frida events into a feature window."""

    def __init__(self):
        self._lock = Lock()
        self.reset()

    def reset(self):
        """Start a fresh aggregation window."""
        with getattr(self, "_lock", Lock()):
            self._counts = Counter()
            self._paths = set()
            self._depths = []
            self._event_count = 0
            self._invalid_events = 0

    @staticmethod
    def _path_depth(path: str) -> int:
        parts = [part for part in path.split("/") if part]
        return len(parts)

    def add_event(self, event: dict[str, Any]) -> bool:
        """Add one observed Frida event. Return whether it was accepted."""
        if not isinstance(event, dict):
            with self._lock:
                self._invalid_events += 1
            return False

        layer = event.get("layer")
        event_type = event.get("event")

        if not isinstance(layer, str) or not isinstance(event_type, str):
            with self._lock:
                self._invalid_events += 1
            return False

        with self._lock:
            self._event_count += 1

            if layer == "MPVG":
                if event_type == "checkSelfPermission":
                    self._counts[
                        "MPVG_checkSelfPermission_count"
                    ] += 1
                elif event_type == "requestPermissions":
                    self._counts[
                        "MPVG_requestPermissions_count"
                    ] += 1

            elif layer == "CAIT":
                if event_type == "camera_id_list":
                    self._counts["CAIT_camera_id_list_count"] += 1
                elif event_type == "camera_open":
                    self._counts["CAIT_camera_open_count"] += 1

            elif layer == "EAP":
                if event_type == "cipher_doFinal":
                    self._counts["EAP_cipher_doFinal_count"] += 1

            elif layer == "SFIM":
                feature_by_event = {
                    "file_delete": "SFIM_file_delete_count",
                    "file_read_open": "SFIM_file_read_open_count",
                    "file_rename": "SFIM_file_rename_count",
                    "file_write_open": "SFIM_file_write_open_count",
                }

                feature = feature_by_event.get(event_type)
                if feature:
                    self._counts[feature] += 1

                paths = []

                if event_type in PATH_EVENTS:
                    if event_type == "file_rename":
                        source = event.get("source")
                        destination = event.get("destination")

                        if isinstance(source, str) and source:
                            paths.append(source)
                        if isinstance(destination, str) and destination:
                            paths.append(destination)
                    else:
                        path = event.get("path")
                        if isinstance(path, str) and path:
                            paths.append(path)

                for path in paths:
                    self._paths.add(path)
                    self._depths.append(self._path_depth(path))

                    extension = PurePosixPath(path.lower()).suffix
                    extension_feature = EXTENSION_FEATURES.get(extension)

                    if extension_feature:
                        self._counts[extension_feature] += 1

            return True

    def snapshot(self, reset: bool = False) -> dict[str, Any]:
        """Return current feature values and explicitly unavailable features."""
        with self._lock:
            features = {}

            for name in REQUIRED_FEATURES:
                if name in UNAVAILABLE_FEATURES:
                    continue

                if name == "avg_depth":
                    features[name] = (
                        sum(self._depths) / len(self._depths)
                        if self._depths
                        else 0.0
                    )
                elif name == "unique_path_count":
                    features[name] = len(self._paths)
                elif name == "file_event_count":
                    features[name] = sum(
                        self._counts[key]
                        for key in (
                            "SFIM_file_delete_count",
                            "SFIM_file_read_open_count",
                            "SFIM_file_rename_count",
                            "SFIM_file_write_open_count",
                        )
                    )
                else:
                    features[name] = self._counts.get(name, 0)

            result = {
                "features": features,
                "available": sorted(features.keys()),
                "unavailable": sorted(UNAVAILABLE_FEATURES),
                "complete": not UNAVAILABLE_FEATURES,
                "observed_event_count": self._event_count,
                "invalid_event_count": self._invalid_events,
                "unique_observed_paths": len(self._paths),
            }

            if reset:
                self._counts.clear()
                self._paths.clear()
                self._depths.clear()
                self._event_count = 0
                self._invalid_events = 0

            return result
