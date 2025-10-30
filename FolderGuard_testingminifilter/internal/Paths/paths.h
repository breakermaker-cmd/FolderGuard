#pragma once

#include <fltKernel.h>

namespace FolderGuard {

	namespace Paths {

		void Init();
		void Cleanup();
		void Add(const WCHAR* path);
		BOOLEAN IsProtected(PUNICODE_STRING filePath);
		void DiscoverDefaultPaths();

	}

}


