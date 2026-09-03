from fastapi import UploadFile, HTTPException
from app.parsers.generic_parser import parse_log_text
from typing import List, Dict, Any

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB limit requirement

async def ingest_log_file(file: UploadFile) -> List[Dict[str, Any]]:
    """
    Ingests log file uploads up to 10MB limit and runs normalized parsing.
    """
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"File size exceeds 10MB limit ({len(contents) / (1024*1024):.2f}MB provided)."
        )

    try:
        text = contents.decode("utf-8", errors="replace")
        parsed_events = parse_log_text(text)
        return parsed_events
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse log file: {str(e)}")
