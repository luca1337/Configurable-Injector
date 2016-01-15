#pragma once


namespace Configurable_Injector {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Xml;
	using namespace System::Runtime::InteropServices;

	[DllImport("user32", CharSet=CharSet::Auto)]
	extern "C" int GetClassNameA( int hwnd, char* szClassName, int nMaxCount );

	[DllImport("utility_public.dll", CharSet=CharSet::Auto, CallingConvention=CallingConvention::Cdecl)]
	extern "C" bool RequestDebugPrivs();

	[DllImport("utility_public.dll", CharSet=CharSet::Auto, CallingConvention=CallingConvention::Cdecl)]
	extern "C" bool __cdecl InjectLibrary( wchar_t *szLibrary, void *hProcess );

	/// <summary>
	/// Summary for Form1
	///
	/// WARNING: If you change the name of this class, you will need to change the
	///          'Resource File Name' property for the managed resource compiler tool
	///          associated with all .resx files this class depends on.  Otherwise,
	///          the designers will not be able to interact properly with localized
	///          resources associated with this form.
	/// </summary>
	public ref class Form1 : public System::Windows::Forms::Form
	{
	public:
		Form1(void)
		{
			InitializeComponent();
			//
			//TODO: Add the constructor code here
			//
		}

	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~Form1()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::PictureBox^  pictureBox1;
	protected: 
	private: System::Windows::Forms::GroupBox^  groupBox1;
	private: System::Windows::Forms::Label^  label1;
	private: System::Windows::Forms::Label^  label2;
	private: System::Windows::Forms::Label^  label3;
	private: System::Windows::Forms::Label^  label4;
	private: System::Windows::Forms::Timer^  timer1;
	private: System::Windows::Forms::Label^  label5;
	private: System::ComponentModel::IContainer^  components;

	private:
		/// <summary>
		/// Required designer variable.
		/// </summary>


#pragma region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		void InitializeComponent(void)
		{
			this->components = (gcnew System::ComponentModel::Container());
			System::ComponentModel::ComponentResourceManager^  resources = (gcnew System::ComponentModel::ComponentResourceManager(Form1::typeid));
			this->pictureBox1 = (gcnew System::Windows::Forms::PictureBox());
			this->groupBox1 = (gcnew System::Windows::Forms::GroupBox());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->timer1 = (gcnew System::Windows::Forms::Timer(this->components));
			this->label5 = (gcnew System::Windows::Forms::Label());
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^  >(this->pictureBox1))->BeginInit();
			this->groupBox1->SuspendLayout();
			this->SuspendLayout();
			// 
			// pictureBox1
			// 
			this->pictureBox1->Image = (cli::safe_cast<System::Drawing::Image^  >(resources->GetObject(L"pictureBox1.Image")));
			this->pictureBox1->Location = System::Drawing::Point(12, 12);
			this->pictureBox1->Name = L"pictureBox1";
			this->pictureBox1->Size = System::Drawing::Size(251, 211);
			this->pictureBox1->TabIndex = 0;
			this->pictureBox1->TabStop = false;
			// 
			// groupBox1
			// 
			this->groupBox1->Controls->Add(this->label5);
			this->groupBox1->Controls->Add(this->label4);
			this->groupBox1->Controls->Add(this->label3);
			this->groupBox1->Controls->Add(this->label2);
			this->groupBox1->Controls->Add(this->label1);
			this->groupBox1->Location = System::Drawing::Point(12, 229);
			this->groupBox1->Name = L"groupBox1";
			this->groupBox1->Size = System::Drawing::Size(250, 130);
			this->groupBox1->TabIndex = 1;
			this->groupBox1->TabStop = false;
			this->groupBox1->Text = L"Information";
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(6, 66);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(128, 12);
			this->label4->TabIndex = 3;
			this->label4->Text = L"Injection Class: <NULL>";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(6, 110);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(83, 12);
			this->label3->TabIndex = 2;
			this->label3->Text = L"MOTD: <NULL>";
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(6, 45);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(144, 12);
			this->label2->TabIndex = 1;
			this->label2->Text = L"Injection Window: <NULL>";
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(6, 24);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(158, 12);
			this->label1->TabIndex = 0;
			this->label1->Text = L"Injection Executable: <NULL>";
			// 
			// timer1
			// 
			this->timer1->Interval = 10;
			this->timer1->Tick += gcnew System::EventHandler(this, &Form1::timer1_Tick);
			// 
			// label5
			// 
			this->label5->AutoSize = true;
			this->label5->Location = System::Drawing::Point(6, 88);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(138, 12);
			this->label5->TabIndex = 4;
			this->label5->Text = L"Injecting Module: <NULL>";
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 12);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(274, 372);
			this->Controls->Add(this->groupBox1);
			this->Controls->Add(this->pictureBox1);
			this->Font = (gcnew System::Drawing::Font(L"Verdana", 6.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point, 
				static_cast<System::Byte>(0)));
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedDialog;
			this->MaximizeBox = false;
			this->Name = L"Form1";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"CRemoteLoader";
			this->Load += gcnew System::EventHandler(this, &Form1::Form1_Load);
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^  >(this->pictureBox1))->EndInit();
			this->groupBox1->ResumeLayout(false);
			this->groupBox1->PerformLayout();
			this->ResumeLayout(false);

		}
#pragma endregion
	private:
		System::String ^m_ExecutableName;
		System::String ^m_WindowName;
		System::String ^m_ClassName;
		System::String ^m_ModuleName;
		System::Collections::Generic::List<System::String ^>^ m_MotdMessages;

	private: System::String^ GetXmlString( XmlDocument^ xmlDoc, System::String^ Tag, int iChildNum ) {

				 XmlNodeList ^items = xmlDoc->GetElementsByTagName( Tag );

				 if( !items->Count )
				 {
					 return nullptr;
				 }

				 if( !items->Item(0)->ChildNodes->Count )
				 {
					 return nullptr;
				 }
				 else
				 {
					 if( items->Item(0)->ChildNodes->Count >= iChildNum )
					 {
						 return items->Item( 0 )->ChildNodes->Item( iChildNum )->Value;
					 }
				 }

				 return nullptr;
			 }

	private: System::Void Form1_Load(System::Object^  sender, System::EventArgs^  e) {

				 RequestDebugPrivs();

				 XmlDocument^ xmlDoc = gcnew XmlDocument();

				 xmlDoc->Load( "config.xml" );

				 m_ExecutableName	= GetXmlString( xmlDoc, "exe", 0 );
				 m_WindowName		= GetXmlString( xmlDoc, "win", 0 );
				 m_ClassName		= GetXmlString( xmlDoc, "cls", 0 );
				 m_ModuleName		= GetXmlString( xmlDoc, "mod", 0 );

				 if( m_ExecutableName == nullptr )
					 this->label1->Text = "Injection Executable: NONE";
				 else
					 this->label1->Text = "Injection Executable: " + m_ExecutableName;

				 if( m_WindowName == nullptr )
					 this->label2->Text = "Injection Window: NONE";
				 else
					 this->label2->Text = "Injection Window: " + m_WindowName;

				 if( m_ClassName == nullptr )
					 this->label4->Text = "Injection Class: NONE";
				 else
					 this->label4->Text = "Injection Class: " + m_ClassName;

				 if( m_ModuleName == nullptr )
				 {
					 System::Windows::Forms::MessageBox::Show(
						 "No injection module set...configure the XML file!",
						 "ERROR",
						 System::Windows::Forms::MessageBoxButtons::OK,
						 System::Windows::Forms::MessageBoxIcon::Error );

					 Application::Exit();
				 }
				 else
				 {
					 this->label5->Text = "Injection Module: " + m_ModuleName;
				 }

				 m_MotdMessages = gcnew System::Collections::Generic::List<System::String ^>();

				 XmlNodeList ^MOTDITEMS = xmlDoc->GetElementsByTagName( "motd" );

				 for( int i = 0; i < MOTDITEMS->Count; i++ )
				 {
					 XmlNode ^nodeBase = MOTDITEMS->Item( i );

					 if( nodeBase->ChildNodes->Count )
					 {
						 for( int c = 0; c < nodeBase->ChildNodes->Count; c++ )
						 {
							 XmlNode ^nodeChild = nodeBase->ChildNodes->Item( c );

							 m_MotdMessages->Add( nodeChild->InnerText );
						 }
					 }
				 }

				 System::Random^ rand = gcnew System::Random();

				 this->label3->Text = "MOTD: " + m_MotdMessages[ rand->Next( 0, m_MotdMessages->Count ) ]->ToString();

				 this->timer1->Enabled = true;
			 }
	private: System::Void timer1_Tick(System::Object^  sender, System::EventArgs^  e) {
				 array<Diagnostics::Process ^>^ pProcesses = Diagnostics::Process::GetProcesses();
				 
				 for( int i = 0; i < pProcesses->Length; i++ )
				 {
					 Diagnostics::Process ^currentProcess = pProcesses[i];

					 String ^pProcessName = currentProcess->ProcessName + ".exe";

					 bool bMetConditions = false;

					 if( m_ExecutableName != nullptr )
					 {
						 if( m_ExecutableName == pProcessName )
						 {
							 bMetConditions = true;
						 }
					 }

 					 if( m_WindowName != nullptr )
					 {
						 if( m_WindowName == currentProcess->MainWindowTitle )
						 {
							 bMetConditions = true;
						 }
					 }

					 if( m_ClassName != nullptr )
					 {
						 char szClassName[256];
						 
						 if( GetClassNameA( (int)currentProcess->MainWindowHandle.ToPointer(), szClassName, 256 ) != 0 )
						 {
							 System::String ^ClassName = gcnew System::String( szClassName );

							 if( ClassName == m_ClassName )
							 {
								 bMetConditions = true;
							 }
						 }
					 }

					 if( bMetConditions )
					 {
						 wchar_t *wcLibraryString = 
							 (wchar_t *)(void *)System::Runtime::InteropServices::Marshal::StringToHGlobalUni( Application::StartupPath + "\\" + m_ModuleName );

						 int iHandle = currentProcess->Handle.ToInt32();

						 if( InjectLibrary( wcLibraryString, &iHandle ) == true )
						 {
							 timer1->Enabled = false;

							 Application::Exit();
						 }
					 }
				 }
			 }
};
}

