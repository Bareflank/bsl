/ --------------------------------------------------------------------------
// File Map
// --------------------------------------------------------------------------

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bsl
{
    // ----------------------------------------------------------------------
    // Deleters
    // ----------------------------------------------------------------------

    /// Input File Array Deleter
    ///
    /// Instead of deleting memory, the input file array deleter unmaps a
    /// previously mapped file.
    ///
    template<typename T>
    struct ifarray_deleter
    {
        /// Functor
        ///
        /// Unmaps a previous mapped file.
        ///
        /// @param ptr the pointer to unmap
        /// @param size the size of the memory to unmap
        /// @return none
        ///
        auto
        operator()(T *ptr, size_t size) -> void
        {
            munmap(const_cast<std::remove_cv_t<T> *>(ptr), size);    // NOLINT
        }
    };

    // ----------------------------------------------------------------------
    // ifarray
    // ----------------------------------------------------------------------

    /// In File Array
    ///
    /// The ifarray is a dynarray that maps in a file (read-only) using map
    /// functions instead of fstream and C style functions. Once the file is
    /// mapped, you can use the full services of the dynarray to work with the
    /// file as if it were any other array.
    ///
    template<typename T = uint8_t>
    class ifarray : public dynarray<const T, ifarray_deleter<const T>>
    {
        using B = dynarray<const T, ifarray_deleter<const T>>;

    public:
        /// @cond
        using value_type = const typename B::value_type;
        using element_type = const typename B::element_type;
        using index_type = typename B::index_type;
        using difference_type = typename B::difference_type;
        using reference = typename B::const_reference;
        using const_reference = typename B::const_reference;
        using pointer = typename B::const_pointer;
        using const_pointer = typename B::const_pointer;
        using deleter_type = typename B::deleter_type;
        using const_deleter_type = typename B::const_deleter_type;
        using iterator = typename B::const_iterator;
        using const_iterator = typename B::const_iterator;
        using reverse_iterator = typename B::const_reverse_iterator;
        using const_reverse_iterator = typename B::const_reverse_iterator;
        /// @endcond

    public:
        /// Default Constructor
        ///
        /// Constructs an farray that does not map in a file.
        ///
        /// @expects
        /// @ensures empty() == true
        ///
        constexpr ifarray() noexcept
        {
            bsl_ensures_terminate(this->empty());
        }

        /// Filename Constructor
        ///
        /// Constructs an ifarray by opening the file provided by filename,
        /// and ensuring the dynarray contains the contents of the desired file.
        /// If possible, this constructor will gain access to the contents of
        /// the file by using the OS's mapping facilities instead of using
        /// C++ or C style file operations.
        ///
        /// If the file cannot be opened for whatever reason, this function
        /// will throw an exception.
        ///
        /// @expects filename.empty() == false
        /// @ensures
        ///
        /// @param filename the name of the file to open for reading.
        ///
        explicit ifarray(const std::string &filename)
        {
            bsl_expects(!filename.empty());

            constexpr const auto flag = O_RDONLY;
            constexpr const auto prot = PROT_READ;
            constexpr const auto perm = MAP_SHARED | MAP_POPULATE;    // NOLINT

            auto fd = this->open_file(filename, flag);
            auto size = this->file_size(fd);
            auto ptr = this->map_file(fd, size, prot, perm);

            close(fd);
            this->reset(static_cast<T *>(ptr), size / sizeof(T));
        }

    protected:
        /// @cond

        constexpr auto
        open_file(const std::string &filename, int prot) -> int
        {
            auto fd = open(filename.c_str(), prot);    // NOLINT
            if (fd == -1) {
                throw std::runtime_error("failed to open file");
            }

            return fd;
        }

        constexpr auto
        file_size(int fd) -> index_type
        {
            struct stat sb = {};
            if (fstat(fd, &sb) == -1) {
                throw std::runtime_error("failed to fstat file");
            }

            return sb.st_size;
        }

        constexpr auto
        map_file(int fd, index_type size, int prot, int perm) -> void *
        {
            auto ptr = mmap(nullptr, size, prot, perm, fd, 0);
            if (ptr == MAP_FAILED) {    // NOLINT
                throw std::runtime_error("failed to map file");
            }

            return ptr;
        }

        /// @endcond
    };
